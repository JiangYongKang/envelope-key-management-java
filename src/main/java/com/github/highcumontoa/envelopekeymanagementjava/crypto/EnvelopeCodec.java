package com.github.highcumontoa.envelopekeymanagementjava.crypto;

import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 信封密文的拼装与解析。
 *
 * <p>文本格式（二进制段使用 Base64URL 无填充，段间以 '.' 分隔）：
 * <pre>
 * EKM1:&lt;主密钥版本号&gt;.&lt;b64 keyId&gt;.&lt;b64 wrappingIv&gt;.&lt;b64 wrappedDek&gt;.&lt;b64 payloadIv&gt;.&lt;b64 payloadCiphertext&gt;
 * </pre>
 * 主密钥版本号是密文对密钥版本的“显式引用”：为明文十进制，供路由查版本；
 * 它同时被包裹层与负载层 GCM 的 AAD 绑定，因此把它改成另一个<b>存在</b>的
 * 版本会在标签校验时暴露为 {@link ErrorCode#CIPHERTEXT_TAMPERED}，改成
 * <b>不存在</b>的版本则在查表阶段明确报 {@link ErrorCode#KEY_VERSION_NOT_FOUND}。
 *
 * <p>错误归类：段数错误、Base64 非法、长度非法等纯结构问题一律归为
 * {@link ErrorCode#CIPHERTEXT_MALFORMED}（含被截断）；结构正确但认证标签
 * 不匹配归为 {@link ErrorCode#CIPHERTEXT_TAMPERED}。
 */
public class EnvelopeCodec {

    /** 密文格式魔数与版本前缀。 */
    public static final String PREFIX = "EKM1:";
    /** GCM 密文至少包含 16 字节标签。 */
    private static final int MIN_GCM_BLOB_LENGTH = 16;

    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public EnvelopeCodec(CryptoService cryptoService) {
        // cryptoService 保留以便未来扩展；当前编解码不做密码学操作
    }

    public String encode(EnvelopeParts parts) {
        if (parts == null || parts.keyId() == null || parts.keyId().isBlank()) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "待编码的密文部件不完整");
        }
        if (parts.masterVersion() <= 0) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "主密钥版本号必须为正整数");
        }
        return PREFIX
                + parts.masterVersion() + '.'
                + b64(parts.keyId().getBytes(StandardCharsets.UTF_8)) + '.'
                + b64(parts.wrappingIv()) + '.'
                + b64(parts.wrappedDek()) + '.'
                + b64(parts.payloadIv()) + '.'
                + b64(parts.payloadCiphertext());
    }

    /**
     * 严格解析密文。任何结构层面的非法输入都抛
     * {@link ErrorCode#CIPHERTEXT_MALFORMED}，绝不返回残缺部件。
     */
    public EnvelopeParts parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_MALFORMED, "密文为空");
        }
        if (!encoded.startsWith(PREFIX)) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_MALFORMED,
                    "密文缺少前缀 " + PREFIX);
        }
        String body = encoded.substring(PREFIX.length());
        String[] tokens = body.split("\\.", -1);
        if (tokens.length != 6) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_MALFORMED,
                    "密文段数应为 6，实际为 " + tokens.length + "（可能被截断或伪造）");
        }
        int masterVersion;
        try {
            masterVersion = Integer.parseUnsignedInt(tokens[0]);
        } catch (NumberFormatException e) {
            throw malformed("主密钥版本号不是合法数字: '" + tokens[0] + "'");
        }
        if (masterVersion <= 0) {
            throw malformed("主密钥版本号必须为正整数: " + masterVersion);
        }
        String keyId;
        byte[] wrappingIv;
        byte[] wrappedDek;
        byte[] payloadIv;
        byte[] payloadCiphertext;
        try {
            keyId = new String(unb64(tokens[1], "keyId"), StandardCharsets.UTF_8);
            wrappingIv = unb64(tokens[2], "wrappingIv");
            wrappedDek = unb64(tokens[3], "wrappedDek");
            payloadIv = unb64(tokens[4], "payloadIv");
            payloadCiphertext = unb64(tokens[5], "payloadCiphertext");
        } catch (IllegalArgumentException e) {
            throw new EnvelopeException(ErrorCode.CIPHERTEXT_MALFORMED,
                    "密文 Base64 解码失败（可能被截断或含非法字符）: " + e.getMessage(), e);
        }
        if (keyId.isBlank()) {
            throw malformed("keyId 为空");
        }
        if (wrappingIv.length != CryptoService.IV_LENGTH_BYTES) {
            throw malformed("wrappingIv 长度非法: " + wrappingIv.length);
        }
        if (payloadIv.length != CryptoService.IV_LENGTH_BYTES) {
            throw malformed("payloadIv 长度非法: " + payloadIv.length);
        }
        if (wrappedDek.length < MIN_GCM_BLOB_LENGTH) {
            throw malformed("wrappedDek 长度小于认证标签，密文被截断");
        }
        if (payloadCiphertext.length < MIN_GCM_BLOB_LENGTH) {
            throw malformed("payloadCiphertext 长度小于认证标签，密文被截断");
        }
        return new EnvelopeParts(keyId, masterVersion, wrappingIv, wrappedDek, payloadIv, payloadCiphertext);
    }

    private String b64(byte[] data) {
        if (data == null || data.length == 0) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "不允许编码空字段");
        }
        return encoder.encodeToString(data);
    }

    private byte[] unb64(String token, String field) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException(field + " 段为空");
        }
        return decoder.decode(token);
    }

    private EnvelopeException malformed(String reason) {
        return new EnvelopeException(ErrorCode.CIPHERTEXT_MALFORMED, "密文结构非法: " + reason);
    }
}
