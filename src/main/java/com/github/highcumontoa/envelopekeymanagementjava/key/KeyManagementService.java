package com.github.highcumontoa.envelopekeymanagementjava.key;

import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;

/**
 * 密钥层级的核心服务：
 * <ul>
 *     <li>主密钥（KEK，AES-256）长期保存于 {@link LocalKeyStore}，只用于加解密数据密钥；</li>
 *     <li>数据密钥（DEK，AES-256）每次加密请求新生成一把，用当前版本 KEK 以 AES-GCM
 *     包装后随密文保存，明文 DEK 只在单次请求内存在于内存。</li>
 * </ul>
 * 解包时按密文中携带的 KEK 版本取历史主密钥，因此旧版本密文在任意次轮换后仍可解密。
 */
@Component
public class KeyManagementService {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);

    static final String WRAP_TRANSFORMATION = "AES/GCM/NoPadding";
    static final int GCM_IV_LENGTH = 12;
    static final int GCM_TAG_BITS = 128;
    static final int DEK_BITS = 256;
    static final int DEK_ID_BYTES = 16;

    private final LocalKeyStore keyStore;
    private final SecureRandom secureRandom = new SecureRandom();

    public KeyManagementService(LocalKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    /** 用当前版本主密钥生成并包装一把新的数据密钥。 */
    public DataKey generateDataKey() {
        MasterKey kek = keyStore.current();
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(DEK_BITS, secureRandom);
            SecretKey dek = generator.generateKey();
            byte[] plaintextDek = dek.getEncoded();

            byte[] iv = randomIv();
            Cipher cipher = Cipher.getInstance(WRAP_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek.getRawKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] wrappedBody = cipher.doFinal(plaintextDek);
            byte[] wrapped = new byte[GCM_IV_LENGTH + wrappedBody.length];
            System.arraycopy(iv, 0, wrapped, 0, GCM_IV_LENGTH);
            System.arraycopy(wrappedBody, 0, wrapped, GCM_IV_LENGTH, wrappedBody.length);

            String dekId = randomDekId();
            Arrays.fill(plaintextDek, (byte) 0);
            log.debug("生成数据密钥 dekId={} kekVersion={}", dekId, kek.getVersion());
            return new DataKey(dekId, kek.getVersion(), dek.getEncoded(), wrapped, Instant.now());
        } catch (GeneralSecurityException e) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "生成数据密钥失败", e);
        }
    }

    /**
     * 按指定主密钥版本解包数据密钥。
     *
     * @throws ApiException KEY_VERSION_NOT_FOUND 版本不存在；CIPHERTEXT_TAMPERED 包装密文认证失败
     */
    public byte[] unwrapDataKey(int masterKeyVersion, byte[] wrappedDek) {
        MasterKey kek = keyStore.findByVersion(masterKeyVersion);
        if (kek == null) {
            throw ApiException.of(ErrorCode.KEY_VERSION_NOT_FOUND, "主密钥版本 " + masterKeyVersion);
        }
        if (wrappedDek == null || wrappedDek.length <= GCM_IV_LENGTH) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                    "包装数据密钥长度不足，至少需要 " + (GCM_IV_LENGTH + 1) + " 字节");
        }
        try {
            byte[] iv = Arrays.copyOfRange(wrappedDek, 0, GCM_IV_LENGTH);
            byte[] body = Arrays.copyOfRange(wrappedDek, GCM_IV_LENGTH, wrappedDek.length);
            Cipher cipher = Cipher.getInstance(WRAP_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek.getRawKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(body);
        } catch (GeneralSecurityException e) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TAMPERED,
                    "数据密钥包装层 GCM 认证失败（主密钥版本=" + masterKeyVersion + "，DEK 密文可能被篡改）");
        }
    }

    /** 触发一次主密钥轮换，返回新版本主密钥。 */
    public MasterKey rotateMasterKey() {
        return keyStore.rotate();
    }

    public MasterKey currentMasterKey() {
        return keyStore.current();
    }

    private byte[] randomIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private String randomDekId() {
        byte[] id = new byte[DEK_ID_BYTES];
        secureRandom.nextBytes(id);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(id);
    }
}
