package com.github.highcumontoa.envelopekeymanagementjava.service;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.DataKey;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyVersion;
import com.github.highcumontoa.envelopekeymanagementjava.store.DataKeyStore;
import com.github.highcumontoa.envelopekeymanagementjava.store.MasterKeyStore;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 密钥生命周期管理。
 *
 * <p>层级模型：主密钥（MK，按版本保存）包裹数据密钥（DEK），DEK 加密业务负载。
 * 明文 DEK 永不落盘，只在单次请求内短暂出现。
 *
 * <p>轮换并发语义（“窗口合批”）：
 * <ul>
 *   <li>某个轮换请求成为领头条目后，在它真正写新版本的<b>轮换窗口</b>内到达的其它
 *       轮换请求（含重复点击）都会等待，窗口结束后复用同一个新版本——
 *       因此并发/重复轮换绝不产生重复版本，也不会打断进行中的轮换。</li>
 *   <li>窗口结束后状态立即复位，之后到来的请求会正常开启下一轮、产生新版本。</li>
 *   <li>真正写新版本的动作发生在轮换锁外，加解密路径不获取该锁；主密钥存储的
 *       读取与原子落盘保证任何时刻读到的版本都完整一致。</li>
 * </ul>
 */
public class KeyManagementService {

    /** generateDataKey 的产物：落盘的包裹记录 + 仅供当次请求使用的明文 DEK。 */
    public record GeneratedDataKey(DataKey record, byte[] plaintextDek) {
    }

    /** rotateMasterKey 的产物：新版本，以及本次请求是否被合批（复用他人窗口结果）。 */
    public record RotationResult(KeyVersion version, boolean coalesced) {
    }

    private final MasterKeyStore masterKeyStore;
    private final DataKeyStore dataKeyStore;
    private final CryptoService cryptoService;
    private final AuditService auditService;

    /** 轮换锁；以下状态仅在持锁时读写。 */
    private final Object rotationLock = new Object();
    /** 是否正处于某个轮换窗口。 */
    private boolean rotating = false;
    /** 本轮换窗口产出的新版本（窗口内等待者合批复用它）。 */
    private KeyVersion windowResult = null;
    /** 本轮换窗口失败时的异常。 */
    private RuntimeException windowFailure = null;

    public KeyManagementService(MasterKeyStore masterKeyStore,
                                DataKeyStore dataKeyStore,
                                CryptoService cryptoService,
                                AuditService auditService) {
        this.masterKeyStore = masterKeyStore;
        this.dataKeyStore = dataKeyStore;
        this.cryptoService = cryptoService;
        this.auditService = auditService;
    }

    /**
     * 生成一把新数据密钥：取当前最新主密钥版本包裹后落盘。
     * 明文 DEK 仅通过返回值交给当次加密请求，不写入任何存储。
     */
    public GeneratedDataKey generateDataKey() {
        // 先快照“当前版本”，保证即使随后立刻发生轮换，记录的 masterVersion
        // 也与实际包裹用的密钥一致（版本永不删除，旧版本以后照样能解）。
        KeyVersion master = masterKeyStore.current();
        String keyId = UUID.randomUUID().toString();
        byte[] dek = cryptoService.generateRandomBytes(CryptoService.KEY_LENGTH_BYTES);
        byte[] wrappingIv = cryptoService.generateRandomBytes(CryptoService.IV_LENGTH_BYTES);
        byte[] wrapped;
        try {
            wrapped = cryptoService.aesGcmEncrypt(
                    master.masterKey(), wrappingIv, dek, wrapAad(master.version(), keyId));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("数据密钥包裹失败: " + e.getMessage(), e);
        }
        DataKey record = new DataKey(keyId, master.version(), wrapped, wrappingIv, Instant.now(), true);
        dataKeyStore.put(record);
        auditService.record("system", AuditAction.GENERATE_DATA_KEY, true, keyId,
                "使用主密钥 v" + master.version() + " 生成并包裹数据密钥");
        return new GeneratedDataKey(record, dek);
    }

    /**
     * 轮换主密钥。
     *
     * @return 新的主密钥版本；轮换窗口内的并发/重复请求合批复用同一版本
     */
    public RotationResult rotateMasterKey() {
        boolean leader;
        KeyVersion result;
        RuntimeException failure;

        synchronized (rotationLock) {
            if (rotating) {
                // 已有轮换在进行：等待该窗口结束，复用其结果（合批）
                while (rotating) {
                    awaitWindowEnd();
                }
                if (windowFailure != null) {
                    RuntimeException f = windowFailure;
                    auditService.record("system", AuditAction.ROTATE, false, "master",
                            "被合批的轮换请求感知到窗口失败: " + f.getMessage());
                    throw f;
                }
                KeyVersion shared = windowResult;
                auditService.record("system", AuditAction.ROTATE, true, "master",
                        "并发/重复轮换请求合批复用 v" + shared.version());
                return new RotationResult(shared, true);
            }
            // 开启一个新的轮换窗口，本线程为领头条目
            rotating = true;
            windowResult = null;
            windowFailure = null;
            leader = true;
        }

        try {
            result = performRotation();
        } catch (RuntimeException e) {
            synchronized (rotationLock) {
                windowFailure = e;
                rotating = false;
                rotationLock.notifyAll();
            }
            if (leader) {
                auditService.record("system", AuditAction.ROTATE, false, "master",
                        "主密钥轮换失败: " + e.getMessage());
            }
            throw e;
        }

        synchronized (rotationLock) {
            windowResult = result;
            rotating = false;
            rotationLock.notifyAll();
        }
        auditService.record("system", AuditAction.ROTATE, true, "master",
                "主密钥轮换成功，新增 v" + result.version());
        return new RotationResult(result, false);
    }

    private void awaitWindowEnd() {
        try {
            rotationLock.wait();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "等待主密钥轮换时被中断");
        }
    }

    /**
     * 真正生成并追加新版本。子类可覆盖以注入延迟，做轮换并发测试。
     * 加解密路径不持轮换锁，故该方法执行期间加解密照常进行。
     */
    protected KeyVersion performRotation() {
        onBeforeAppend();
        byte[] material = cryptoService.generateRandomBytes(CryptoService.KEY_LENGTH_BYTES);
        return masterKeyStore.append(material);
    }

    /** 并发测试钩子：新版本落盘前执行动作（默认空实现）。 */
    protected void onBeforeAppend() {
    }

    /**
     * 解析密文引用的主密钥版本是否真实存在；不存在直接抛
     * {@link ErrorCode#KEY_VERSION_NOT_FOUND}。
     */
    public KeyVersion requireMasterVersion(int referencedVersion) {
        return masterKeyStore.requireVersion(referencedVersion);
    }

    /**
     * 解包数据密钥：按引用的主版本号查对应版本主密钥解密并验签。
     * 版本不存在 -> {@link ErrorCode#KEY_VERSION_NOT_FOUND}；
     * 标签不匹配（包裹密文/版本/keyId 被改动）-> {@link ErrorCode#CIPHERTEXT_TAMPERED}。
     */
    public byte[] unwrapDataKey(DataKey dataKey, int referencedVersion) {
        KeyVersion master = masterKeyStore.requireVersion(referencedVersion);
        try {
            return cryptoService.aesGcmDecrypt(
                    master.masterKey(),
                    dataKey.wrappingIv(),
                    dataKey.wrappedKey(),
                    wrapAad(referencedVersion, dataKey.keyId()));
        } catch (AEADBadTagException e) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_TAMPERED,
                    "数据密钥包裹层认证标签不匹配（keyId/版本/包裹密文可能被篡改）", e);
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_TAMPERED,
                    "数据密钥解包失败，密文可能已损坏: " + e.getMessage(), e);
        }
    }

    public KeyVersion currentMasterKey() {
        return masterKeyStore.current();
    }

    public List<KeyVersion> listMasterVersions() {
        return masterKeyStore.loadAll();
    }

    /** 包裹层 AAD：把版本与 keyId 绑进认证标签。 */
    static byte[] wrapAad(int masterVersion, String keyId) {
        return ("EKM1|v=" + masterVersion + "|key=" + keyId + "|layer=wrap")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** 负载层 AAD：把版本与 keyId 绑进负载认证标签。 */
    static byte[] payloadAad(int masterVersion, String keyId) {
        return ("EKM1|v=" + masterVersion + "|key=" + keyId + "|layer=payload")
                .getBytes(StandardCharsets.UTF_8);
    }
}
