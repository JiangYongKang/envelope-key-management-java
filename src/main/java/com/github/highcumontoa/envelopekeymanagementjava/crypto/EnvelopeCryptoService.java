package com.github.highcumontoa.envelopekeymanagementjava.crypto;

import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.DataKey;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyManagementService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 信封加解密服务。
 *
 * <p>加密：向 KMS 申请一把全新 DEK（每次调用密钥不同），DEK 明文加密负载后随即丢弃，
 * 输出中只保留“被 KEK 包装的 DEK + 负载 IV + 负载密文”。由于 DEK 与 IV 每次随机生成，
 * 同一明文每次加密结果必然不同，但都能解回原值。</p>
 *
 * <p>解密：先解析结构（格式/截断错误在此阶段被拒绝），再按密文携带的 KEK 版本解包 DEK
 * （版本不存在在此阶段被拒绝），最后用 DEK 做 GCM 认证解密，任何字节级篡改都会导致
 * AEAD 标签校验失败并被拒绝，全程不可能返回错误的明文。</p>
 */
@Component
public class EnvelopeCryptoService {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCryptoService.class);

    static final String PAYLOAD_TRANSFORMATION = "AES/GCM/NoPadding";
    static final int PAYLOAD_TAG_BITS = 128;

    private final KeyManagementService keyManagementService;
    private final SecureRandom secureRandom = new SecureRandom();

    public EnvelopeCryptoService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /** 加密结果：Base64 密文及其使用的 KEK 版本与 DEK ID。 */
    public record Encrypted(String ciphertext, int masterKeyVersion, String dataKeyId) {
    }

    /** 加密一段 UTF-8 明文。 */
    public Encrypted encrypt(String plaintext) {
        if (plaintext == null) {
            throw ApiException.of(ErrorCode.INVALID_PARAMETER, "plaintext 不能为 null");
        }
        DataKey dek = keyManagementService.generateDataKey();
        try {
            byte[] iv = new byte[EnvelopeCiphertext.PAYLOAD_IV_LENGTH];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(PAYLOAD_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek.getPlaintextKey(), "AES"),
                    new GCMParameterSpec(PAYLOAD_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            EnvelopeCiphertext envelope = new EnvelopeCiphertext(
                    dek.getMasterKeyVersion(), dek.getId(), dek.getEncryptedKey(), iv, ciphertext);
            String encoded = envelope.encode();
            log.debug("信封加密完成 dekId={} kekVersion={} plaintextBytes={} ciphertextChars={}",
                    dek.getId(), dek.getMasterKeyVersion(),
                    plaintext.getBytes(StandardCharsets.UTF_8).length, encoded.length());
            return new Encrypted(encoded, dek.getMasterKeyVersion(), dek.getId());
        } catch (GeneralSecurityException e) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "负载加密失败", e);
        } finally {
            Arrays.fill(dek.getPlaintextKey(), (byte) 0);
        }
    }

    /**
     * 解密 Base64 信封密文。任何格式、版本或完整性问题都抛出带明确错误码的 {@link ApiException}。
     */
    public String decrypt(String encodedCiphertext) {
        if (encodedCiphertext == null || encodedCiphertext.isBlank()) {
            throw ApiException.of(ErrorCode.INVALID_PARAMETER, "ciphertext 为空");
        }
        EnvelopeCiphertext envelope = EnvelopeCiphertext.parse(encodedCiphertext);
        byte[] dekPlain = keyManagementService.unwrapDataKey(
                envelope.getMasterKeyVersion(), envelope.getEncryptedDataKey());
        try {
            Cipher cipher = Cipher.getInstance(PAYLOAD_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dekPlain, "AES"),
                    new GCMParameterSpec(PAYLOAD_TAG_BITS, envelope.getPayloadIv()));
            byte[] plaintext = cipher.doFinal(envelope.getPayloadCiphertext());
            String result = new String(plaintext, StandardCharsets.UTF_8);
            log.debug("信封解密成功 dekId={} kekVersion={} plaintextBytes={}",
                    envelope.getDataKeyId(), envelope.getMasterKeyVersion(), plaintext.length);
            return result;
        } catch (GeneralSecurityException e) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TAMPERED,
                    "负载层 GCM 认证失败（KEK 版本=" + envelope.getMasterKeyVersion()
                            + "，DEK ID=" + envelope.getDataKeyId() + "，密文或 IV/标签可能被篡改）");
        } finally {
            Arrays.fill(dekPlain, (byte) 0);
        }
    }
}
