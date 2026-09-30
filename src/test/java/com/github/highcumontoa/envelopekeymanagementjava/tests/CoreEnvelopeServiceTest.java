package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.AccessControlService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.CallerRegistry;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.key.LocalKeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 信封加解密与主密钥轮换的核心服务测试（无 Spring 容器、无外部服务）。
 */
class CoreEnvelopeServiceTest {

    private static final Logger log = LoggerFactory.getLogger(CoreEnvelopeServiceTest.class);

    @TempDir
    Path tempDir;

    private LocalKeyStore keyStore;
    private KeyManagementService kms;
    private EnvelopeCryptoService crypto;

    @BeforeEach
    void setUp() throws Exception {
        keyStore = new LocalKeyStore(tempDir);
        invokePostConstruct(keyStore);
        kms = new KeyManagementService(keyStore);
        AuditService audit = new AuditService(tempDir.resolve("audit"));
        invokePostConstruct(audit);
        new AccessControlService(new CallerRegistry(), audit);
        crypto = new EnvelopeCryptoService(kms);
    }

    private static void invokePostConstruct(Object bean) throws Exception {
        java.lang.reflect.Method m = bean.getClass().getDeclaredMethod("initialize");
        m.setAccessible(true);
        m.invoke(bean);
    }

    @Test
    @DisplayName("同一明文每次密文不同，但都能解回原值")
    void nonDeterministicEncryptionRoundTrip() {
        String plaintext = "敏感负载-余额=100.00";
        EnvelopeCryptoService.Encrypted c1 = crypto.encrypt(plaintext);
        EnvelopeCryptoService.Encrypted c2 = crypto.encrypt(plaintext);
        log.info("[关键输入] 同一明文加密两次：ciphertext1 长度={}，ciphertext2 长度={}，相等={}",
                c1.ciphertext().length(), c2.ciphertext().length(), c1.ciphertext().equals(c2.ciphertext()));
        assertNotEquals(c1.ciphertext(), c2.ciphertext(), "同一明文的两次密文必须不同（随机 DEK/IV）");
        assertEquals(plaintext, crypto.decrypt(c1.ciphertext()));
        assertEquals(plaintext, crypto.decrypt(c2.ciphertext()));
    }

    @Test
    @DisplayName("篡改密文字节 -> CIPHERTEXT_TAMPERED(INTEGRITY)，且绝不返回明文")
    void tamperedCiphertextRejected() {
        String plaintext = "不可泄露的秘密-42";
        String encoded = crypto.encrypt(plaintext).ciphertext();
        byte[] raw = Base64.getDecoder().decode(encoded);
        // 翻转密文尾部附近一个字节（落在 GCM 密文/标签区域，不破坏结构）
        int idx = raw.length - 3;
        raw[idx] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(raw);
        ApiException ex = assertThrows(ApiException.class, () -> crypto.decrypt(tampered));
        log.info("[判定依据] 翻转字节 idx={} -> code={}({}) message={}",
                idx, ex.getErrorCode(), ex.getErrorCode().getCategory(), ex.getMessage());
        assertEquals(ErrorCode.CIPHERTEXT_TAMPERED, ex.getErrorCode());
    }

    @Test
    @DisplayName("篡改包装 DEK -> CIPHERTEXT_TAMPERED（包装层 GCM 失败）")
    void tamperedWrappedDekRejected() {
        String encoded = crypto.encrypt("payload-x").ciphertext();
        byte[] raw = Base64.getDecoder().decode(encoded);
        // 头部固定为 4+1+4+2+22(dekId) = 33，包装 DEK 从该位置之后开始，翻转其中间字节
        int idx = 40;
        raw[idx] ^= (byte) 0xFF;
        ApiException ex = assertThrows(ApiException.class,
                () -> crypto.decrypt(Base64.getEncoder().encodeToString(raw)));
        log.info("[判定依据] 翻转包装DEK字节 idx={} -> code={}", idx, ex.getErrorCode());
        assertEquals(ErrorCode.CIPHERTEXT_TAMPERED, ex.getErrorCode());
    }

    @Test
    @DisplayName("截断密文 -> CIPHERTEXT_TRUNCATED(CIPHERTEXT)")
    void truncatedCiphertextRejected() {
        String encoded = crypto.encrypt("payload-y").ciphertext();
        String truncated = encoded.substring(0, encoded.length() - 12);
        ApiException ex = assertThrows(ApiException.class, () -> crypto.decrypt(truncated));
        log.info("[关键输入] 截断 12 字符 -> code={}({})", ex.getErrorCode(), ex.getErrorCode().getCategory());
        assertEquals(ErrorCode.CIPHERTEXT_TRUNCATED, ex.getErrorCode());
    }

    @Test
    @DisplayName("魔数被改 -> MALFORMED_CIPHERTEXT(CIPHERTEXT)")
    void malformedMagicRejected() {
        byte[] raw = Base64.getDecoder().decode(crypto.encrypt("z").ciphertext());
        raw[0] = '?';
        ApiException ex = assertThrows(ApiException.class,
                () -> crypto.decrypt(Base64.getEncoder().encodeToString(raw)));
        log.info("[判定依据] 魔数首字节改写 -> code={}", ex.getErrorCode());
        assertEquals(ErrorCode.MALFORMED_CIPHERTEXT, ex.getErrorCode());
    }

    @Test
    @DisplayName("引用不存在的密钥版本 -> KEY_VERSION_NOT_FOUND(KEY)，且密文本身结构完整")
    void unknownKeyVersionRejected() {
        EnvelopeCryptoService.Encrypted encrypted = crypto.encrypt("将引用不存在的版本");
        int oldVersion = encrypted.masterKeyVersion();
        byte[] raw = Base64.getDecoder().decode(encrypted.ciphertext());
        // KEK 版本位于魔数(4) + 结构版本(1) 之后的 4 字节 int，改写为 999
        int fakeVersion = 999;
        byte[] versionBytes = java.nio.ByteBuffer.allocate(4).putInt(fakeVersion).array();
        System.arraycopy(versionBytes, 0, raw, 5, 4);
        ApiException ex = assertThrows(ApiException.class,
                () -> crypto.decrypt(Base64.getEncoder().encodeToString(raw)));
        log.info("[关键输入] KEK 版本 {} 篡改为 {} -> code={}({})",
                oldVersion, fakeVersion, ex.getErrorCode(), ex.getErrorCode().getCategory());
        assertEquals(ErrorCode.KEY_VERSION_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    @DisplayName("主密钥轮换后：新密文使用新版本，历史密文仍可解")
    void rotationPreservesOldCiphertext() {
        String oldPlaintext = "轮换前的数据-历史";
        EnvelopeCryptoService.Encrypted oldEncrypted = crypto.encrypt(oldPlaintext);
        int versionBefore = kms.currentMasterKey().getVersion();

        var newMaster = kms.rotateMasterKey();
        int versionAfter = newMaster.getVersion();
        log.info("[判定依据] 轮换前版本={}，轮换后版本={}", versionBefore, versionAfter);
        assertEquals(versionBefore + 1, versionAfter);

        // 历史密文仍可解
        assertEquals(oldPlaintext, crypto.decrypt(oldEncrypted.ciphertext()));

        // 新密文必须落在新版本
        EnvelopeCryptoService.Encrypted newEncrypted = crypto.encrypt("轮换后的数据-当下");
        log.info("[判定依据] 新密文 kekVersion={}，旧密文 kekVersion={}",
                newEncrypted.masterKeyVersion(), oldEncrypted.masterKeyVersion());
        assertEquals(versionAfter, newEncrypted.masterKeyVersion());
        assertEquals("轮换后的数据-当下", crypto.decrypt(newEncrypted.ciphertext()));
    }

    @Test
    @DisplayName("多轮轮换后任意历史版本密文都能解回")
    void multipleRotations() {
        var v1Cipher = crypto.encrypt("v1-era");
        kms.rotateMasterKey();
        var v2Cipher = crypto.encrypt("v2-era");
        kms.rotateMasterKey();
        var v3Cipher = crypto.encrypt("v3-era");

        assertEquals("v1-era", crypto.decrypt(v1Cipher.ciphertext()));
        assertEquals("v2-era", crypto.decrypt(v2Cipher.ciphertext()));
        assertEquals("v3-era", crypto.decrypt(v3Cipher.ciphertext()));
        log.info("[判定依据] 当前版本={}，三代密文 kek 版本分别为 {},{},{} 均可解密",
                kms.currentMasterKey().getVersion(),
                v1Cipher.masterKeyVersion(), v2Cipher.masterKeyVersion(), v3Cipher.masterKeyVersion());
    }

    @Test
    @DisplayName("空明文作为参数错误处理：null -> INVALID_PARAMETER；空串允许往返")
    void emptyInputHandling() {
        ApiException ex = assertThrows(ApiException.class, () -> crypto.encrypt(null));
        assertEquals(ErrorCode.INVALID_PARAMETER, ex.getErrorCode());
        String emptyCipher = crypto.encrypt("").ciphertext();
        assertEquals("", crypto.decrypt(emptyCipher));
        log.info("[判定依据] null 明文 -> INVALID_PARAMETER；空串密文可正常往返，长度={}",
                emptyCipher.getBytes(StandardCharsets.UTF_8).length);
    }
}
