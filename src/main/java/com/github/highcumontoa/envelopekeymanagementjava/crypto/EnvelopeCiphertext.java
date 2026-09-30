package com.github.highcumontoa.envelopekeymanagementjava.crypto;

import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;

/**
 * 信封密文的二进制结构与序列化。
 *
 * <p>所有长度均为无符号短整型（2 字节，大端序），布局如下：</p>
 * <pre>
 * 偏移  长度              字段
 * 0     4                 魔数 "EKM1"
 * 4     1                 结构版本（当前 = 1）
 * 5     4                 主密钥版本（int32，大端）
 * 9     2                 DEK ID 长度 Ld
 * 11    Ld                DEK ID（UTF-8）
 * 11+Ld 2                 包装 DEK 长度 Lk
 * 13+Ld Lk                包装 DEK（内含 12B IV + AES-GCM(DEK)）
 * ...   2                 负载 IV 长度 Li（当前固定 12）
 * ...   Li                负载 IV
 * ...   4                 负载密文长度 Lc（含 16B GCM 标签）
 * ...   Lc                负载密文 + 标签
 * </pre>
 *
 * <p>错误分类约定：</p>
 * <ul>
 *     <li>{@code MALFORMED_CIPHERTEXT}：Base64 解不开、魔数/结构版本不对；</li>
 *     <li>{@code CIPHERTEXT_TRUNCATED}：头部有效但声明长度与实际字节数不符；</li>
 *     <li>{@code CIPHERTEXT_TAMPERED}：结构完整但 GCM 认证失败（由加解密服务判定）。</li>
 * </ul>
 */
public final class EnvelopeCiphertext {

    public static final byte[] MAGIC = {'E', 'K', 'M', '1'};
    public static final byte FORMAT_VERSION = 1;
    public static final int PAYLOAD_IV_LENGTH = 12;

    private final int masterKeyVersion;
    private final String dataKeyId;
    private final byte[] encryptedDataKey;
    private final byte[] payloadIv;
    private final byte[] payloadCiphertext;

    public EnvelopeCiphertext(int masterKeyVersion, String dataKeyId,
                              byte[] encryptedDataKey, byte[] payloadIv, byte[] payloadCiphertext) {
        this.masterKeyVersion = masterKeyVersion;
        this.dataKeyId = dataKeyId;
        this.encryptedDataKey = encryptedDataKey;
        this.payloadIv = payloadIv;
        this.payloadCiphertext = payloadCiphertext;
    }

    /** 序列化为二进制后做标准 Base64 编码。 */
    public String encode() {
        byte[] dekIdBytes = dataKeyId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int total = MAGIC.length + 1 + 4
                + 2 + dekIdBytes.length
                + 2 + encryptedDataKey.length
                + 2 + payloadIv.length
                + 4 + payloadCiphertext.length;
        ByteBuffer buffer = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        buffer.put(MAGIC);
        buffer.put(FORMAT_VERSION);
        buffer.putInt(masterKeyVersion);
        buffer.putShort((short) dekIdBytes.length);
        buffer.put(dekIdBytes);
        buffer.putShort((short) encryptedDataKey.length);
        buffer.put(encryptedDataKey);
        buffer.putShort((short) payloadIv.length);
        buffer.put(payloadIv);
        buffer.putInt(payloadCiphertext.length);
        buffer.put(payloadCiphertext);
        return Base64.getEncoder().encodeToString(buffer.array());
    }

    /**
     * 解析 Base64 信封密文，只做结构校验，不做任何密码学解密，
     * 因此格式问题永远不会泄露明文，也不会被误判为篡改。
     */
    public static EnvelopeCiphertext parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw ApiException.of(ErrorCode.INVALID_PARAMETER, "ciphertext 为空");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException e) {
            throw ApiException.of(ErrorCode.MALFORMED_CIPHERTEXT, "不是合法的 Base64 编码");
        }
        if (raw.length < MAGIC.length + 1) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                    "总长度 " + raw.length + " 字节，不足以容纳魔数与结构版本");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[i] != MAGIC[i]) {
                throw ApiException.of(ErrorCode.MALFORMED_CIPHERTEXT, "魔数不是 EKM1");
            }
        }
        int pos = MAGIC.length;
        short formatVersion = raw[pos++];
        if (formatVersion != FORMAT_VERSION) {
            throw ApiException.of(ErrorCode.MALFORMED_CIPHERTEXT, "不支持的结构版本 " + formatVersion);
        }
        int masterKeyVersion = readInt(raw, pos, "主密钥版本");
        pos += 4;

        int dekIdLen = readUnsignedShort(raw, pos, "DEK ID 长度");
        pos += 2;
        if (pos + dekIdLen > raw.length) {
            throw truncated("DEK ID", pos + dekIdLen, raw.length);
        }
        String dekId = new String(raw, pos, dekIdLen, java.nio.charset.StandardCharsets.UTF_8);
        pos += dekIdLen;

        int wrappedDekLen = readUnsignedShort(raw, pos, "包装 DEK 长度");
        pos += 2;
        if (pos + wrappedDekLen > raw.length) {
            throw truncated("包装 DEK", pos + wrappedDekLen, raw.length);
        }
        byte[] wrappedDek = Arrays.copyOfRange(raw, pos, pos + wrappedDekLen);
        pos += wrappedDekLen;

        int ivLen = readUnsignedShort(raw, pos, "负载 IV 长度");
        pos += 2;
        if (pos + ivLen > raw.length) {
            throw truncated("负载 IV", pos + ivLen, raw.length);
        }
        byte[] iv = Arrays.copyOfRange(raw, pos, pos + ivLen);
        pos += ivLen;

        int cipherLen = readInt(raw, pos, "负载密文长度");
        pos += 4;
        if (cipherLen < 0 || pos + cipherLen != raw.length) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                    "负载密文声明长度 " + cipherLen + " 与剩余字节 " + (raw.length - pos) + " 不一致");
        }
        byte[] cipher = Arrays.copyOfRange(raw, pos, pos + cipherLen);
        return new EnvelopeCiphertext(masterKeyVersion, dekId, wrappedDek, iv, cipher);
    }

    private static int readInt(byte[] raw, int pos, String field) {
        if (pos + 4 > raw.length) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                    "读取[" + field + "]需要 4 字节，但偏移 " + pos + " 处只剩 " + (raw.length - pos) + " 字节");
        }
        return ((raw[pos] & 0xFF) << 24) | ((raw[pos + 1] & 0xFF) << 16)
                | ((raw[pos + 2] & 0xFF) << 8) | (raw[pos + 3] & 0xFF);
    }

    private static int readUnsignedShort(byte[] raw, int pos, String field) {
        if (pos + 2 > raw.length) {
            throw ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                    "读取[" + field + "]需要 2 字节，但偏移 " + pos + " 处只剩 " + (raw.length - pos) + " 字节");
        }
        return ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
    }

    private static ApiException truncated(String field, int needed, int actualLength) {
        return ApiException.of(ErrorCode.CIPHERTEXT_TRUNCATED,
                "[" + field + "]需要到偏移 " + needed + "，但密文总长仅 " + actualLength);
    }

    public int getMasterKeyVersion() {
        return masterKeyVersion;
    }

    public String getDataKeyId() {
        return dataKeyId;
    }

    public byte[] getEncryptedDataKey() {
        return encryptedDataKey;
    }

    public byte[] getPayloadIv() {
        return payloadIv;
    }

    public byte[] getPayloadCiphertext() {
        return payloadCiphertext;
    }
}
