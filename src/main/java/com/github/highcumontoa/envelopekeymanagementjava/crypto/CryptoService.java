package com.github.highcumontoa.envelopekeymanagementjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * 对称加解密原语（AES-256-GCM），同时保证机密性与完整性。
 * GCM 自带 128 位认证标签：密文或 AAD 任何一位被改动，解密都会失败。
 */
public class CryptoService {

    /** AES-256 密钥长度（字节）。 */
    public static final int KEY_LENGTH_BYTES = 32;
    /** GCM 推荐 IV 长度（字节）。 */
    public static final int IV_LENGTH_BYTES = 12;
    /** 认证标签长度（位）。 */
    private static final int TAG_LENGTH_BITS = 128;
    private static final String TRANSFORM = "AES/GCM/NoPadding";

    private final SecureRandom secureRandom = new SecureRandom();

    /** 生成密码学安全的随机字节（用于密钥与 IV）。 */
    public byte[] generateRandomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * AES-GCM 加密。
     *
     * @param key       32 字节密钥
     * @param iv        12 字节随机 IV（每次加密都必须不同）
     * @param plaintext 明文
     * @param aad       附加认证数据，会被完整性标签保护但不会被加密
     * @return 密文（尾部含 16 字节认证标签）
     */
    public byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        validateKeyAndIv(key, iv);
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    /**
     * AES-GCM 解密。标签校验失败（密文/AAD 被篡改）会抛 AEADBadTagException。
     */
    public byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad)
            throws GeneralSecurityException {
        validateKeyAndIv(key, iv);
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    private void validateKeyAndIv(byte[] key, byte[] iv) {
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("AES 密钥必须为 " + KEY_LENGTH_BYTES + " 字节");
        }
        if (iv == null || iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("GCM IV 必须为 " + IV_LENGTH_BYTES + " 字节");
        }
    }
}
