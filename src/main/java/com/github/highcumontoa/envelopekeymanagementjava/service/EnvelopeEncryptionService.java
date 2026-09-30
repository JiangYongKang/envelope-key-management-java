package com.github.highcumontoa.envelopekeymanagementjava.service;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCodec;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeParts;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.DataKey;
import com.github.highcumontoa.envelopekeymanagementjava.store.DataKeyStore;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * 信封加解密门面（鉴权由调用方/控制层先行完成）。
 *
 * <p>加密：为每次请求新建数据密钥并使用随机 IV，因此同一明文每次产生的密文不同；
 * 密文以文本信封格式返回。解密：先严格解析结构，再依次核对数据密钥存在性、
 * 主密钥版本存在性、版本引用一致性、包裹层与负载层的 GCM 认证标签。
 * 任何一步失败都只抛 {@link EnvelopeException} 且<b>绝不返回任何明文</b>。
 *
 * <p>错误分类见 {@link ErrorCode}：参数错误、密文格式非法（含截断）、
 * 密文被篡改、主密钥版本不存在、数据密钥不存在、越权，彼此可区分。
 */
public class EnvelopeEncryptionService {

    private final KeyManagementService keyManagementService;
    private final DataKeyStore dataKeyStore;
    private final CryptoService cryptoService;
    private final EnvelopeCodec codec;
    private final AuditService auditService;

    public EnvelopeEncryptionService(KeyManagementService keyManagementService,
                                     DataKeyStore dataKeyStore,
                                     CryptoService cryptoService,
                                     EnvelopeCodec codec,
                                     AuditService auditService) {
        this.keyManagementService = keyManagementService;
        this.dataKeyStore = dataKeyStore;
        this.cryptoService = cryptoService;
        this.codec = codec;
        this.auditService = auditService;
    }

    /** 加密明文，返回信封密文。空明文以参数错误拒绝。 */
    public String encrypt(String callerId, String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER,
                    "明文 plaintext 不能为空");
        }
        try {
            KeyManagementService.GeneratedDataKey generated = keyManagementService.generateDataKey();
            DataKey dataKey = generated.record();
            int version = dataKey.masterVersion();
            byte[] payloadIv = cryptoService.generateRandomBytes(CryptoService.IV_LENGTH_BYTES);
            // 负载由 DEK 直接加密；DEK 本身由对应版本主密钥包裹后落盘（信封加密）
            byte[] payloadCiphertext = cryptoService.aesGcmEncrypt(
                    generated.plaintextDek(),
                    payloadIv,
                    plaintext.getBytes(StandardCharsets.UTF_8),
                    KeyManagementService.payloadAad(version, dataKey.keyId()));
            EnvelopeParts parts = new EnvelopeParts(
                    dataKey.keyId(), version,
                    dataKey.wrappingIv(), dataKey.wrappedKey(),
                    payloadIv, payloadCiphertext);
            String ciphertext = codec.encode(parts);
            auditService.record(callerId, AuditAction.ENCRYPT, true, dataKey.keyId(),
                    "加密成功，明文 " + plaintext.getBytes(StandardCharsets.UTF_8).length
                            + " 字节，主密钥 v" + version);
            return ciphertext;
        } catch (EnvelopeException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER,
                    "加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 解密信封密文。任何失败都不返回明文。
     */
    public String decrypt(String callerId, String ciphertext) {
        // 1) 结构解析（失败 -> CIPHERTEXT_MALFORMED）
        EnvelopeParts parts = codec.parse(ciphertext);
        int referencedVersion = parts.masterVersion();

        // 2) 数据密钥存在性（失败 -> DATA_KEY_NOT_FOUND）
        DataKey dataKey = dataKeyStore.get(parts.keyId());
        if (dataKey == null) {
            throw failDecrypt(callerId, parts.keyId(), referencedVersion,
                    new EnvelopeException(ErrorCode.DATA_KEY_NOT_FOUND,
                            "密文引用的数据密钥不存在: keyId=" + parts.keyId()));
        }

        // 3) 主密钥版本存在性（引用了不存在/已停用的版本 -> KEY_VERSION_NOT_FOUND）。
        //    这一步先于一致性比对：引用“根本不存在的版本”与“改成另一个存在版本”
        //    必须给出可区分的结论。
        keyManagementService.requireMasterVersion(referencedVersion);

        // 4) 版本引用一致性（密文版本与数据密钥记录不一致 -> 篡改）
        if (referencedVersion != dataKey.masterVersion()) {
            throw failDecrypt(callerId, parts.keyId(), referencedVersion,
                    new EnvelopeException(ErrorCode.CIPHERTEXT_TAMPERED,
                            "密文声明的主密钥版本 v" + referencedVersion
                                    + " 与数据密钥记录的 v" + dataKey.masterVersion()
                                    + " 不一致，密文版本字段可能被篡改"));
        }

        // 5) 解包 DEK 并验证包裹层标签（失败 -> CIPHERTEXT_TAMPERED）。
        //    关键：以“密文自带”的 wrappedDek/wrappingIv 为准构造解包输入，
        //    存储记录仅用于确认 keyId 存在与其登记版本。这样信封中包裹段的任何
        //    改动都会在主密钥验签时暴露为篡改，而不会被存储里的原值掩盖。
        DataKey carried = new DataKey(dataKey.keyId(), referencedVersion,
                parts.wrappedDek(), parts.wrappingIv(), dataKey.createdAt(), dataKey.enabled());
        byte[] dek = keyManagementService.unwrapDataKey(carried, referencedVersion);

        // 6) 用 DEK 解密负载并验证负载标签（失败 -> CIPHERTEXT_TAMPERED）
        byte[] plaintextBytes;
        try {
            plaintextBytes = cryptoService.aesGcmDecrypt(
                    dek,
                    parts.payloadIv(),
                    parts.payloadCiphertext(),
                    KeyManagementService.payloadAad(referencedVersion, dataKey.keyId()));
        } catch (AEADBadTagException e) {
            throw failDecrypt(callerId, parts.keyId(), referencedVersion,
                    new EnvelopeException(ErrorCode.CIPHERTEXT_TAMPERED,
                            "负载认证标签不匹配，密文负载可能被篡改", e));
        } catch (GeneralSecurityException e) {
            throw failDecrypt(callerId, parts.keyId(), referencedVersion,
                    new EnvelopeException(ErrorCode.CIPHERTEXT_TAMPERED,
                            "负载解密失败，密文可能已损坏: " + e.getMessage(), e));
        }

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        auditService.record(callerId, AuditAction.DECRYPT, true, dataKey.keyId(),
                "解密成功，主密钥 v" + referencedVersion + "，明文 " + plaintextBytes.length + " 字节");
        return plaintext;
    }

    private EnvelopeException failDecrypt(String callerId, String keyId, int version,
                                          EnvelopeException cause) {
        auditService.record(callerId, AuditAction.DECRYPT, false, keyId,
                "解密被拒绝（引用主密钥 v" + version + "）: " + cause.getCode()
                        + " - " + cause.getMessage());
        return cause;
    }
}
