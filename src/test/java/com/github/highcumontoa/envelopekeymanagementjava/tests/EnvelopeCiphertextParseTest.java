package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCiphertext;
import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 结构解析单测：格式非法 / 截断 / 空值必须得到可区分的错误分类。
 */
class EnvelopeCiphertextParseTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCiphertextParseTest.class);

    private String validEnvelopeBase64() {
        // 手工构造一个结构完整的信封：魔数 + v1 + kekVersion=1 + dekId(4B) + wrapped(20B) + iv(12B) + ct(16B)
        byte[] dekId = "dek1".getBytes(StandardCharsets.UTF_8);
        byte[] wrapped = new byte[20];
        byte[] iv = new byte[12];
        byte[] ct = new byte[16];
        java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(
                4 + 1 + 4 + 2 + dekId.length + 2 + wrapped.length + 2 + iv.length + 4 + ct.length);
        b.put(EnvelopeCiphertext.MAGIC).put(EnvelopeCiphertext.FORMAT_VERSION).putInt(1);
        b.putShort((short) dekId.length).put(dekId);
        b.putShort((short) wrapped.length).put(wrapped);
        b.putShort((short) iv.length).put(iv);
        b.putInt(ct.length).put(ct);
        return Base64.getEncoder().encodeToString(b.array());
    }

    @Test
    @DisplayName("合法结构可解析且字段还原正确")
    void parseValid() {
        String encoded = validEnvelopeBase64();
        EnvelopeCiphertext parsed = EnvelopeCiphertext.parse(encoded);
        log.info("[判定依据] 合法密文输入长度={} -> kekVersion={}, dekId={}",
                encoded.length(), parsed.getMasterKeyVersion(), parsed.getDataKeyId());
        assertEquals(1, parsed.getMasterKeyVersion());
        assertEquals("dek1", parsed.getDataKeyId());
        assertEquals(20, parsed.getEncryptedDataKey().length);
        assertEquals(12, parsed.getPayloadIv().length);
        assertEquals(16, parsed.getPayloadCiphertext().length);
    }

    @Test
    @DisplayName("空密文归类为 INVALID_PARAMETER(PARAM)")
    void parseEmpty() {
        ApiException ex = assertThrows(ApiException.class, () -> EnvelopeCiphertext.parse("  "));
        log.info("[关键输入] ciphertext=空白 -> code={}, category={}", ex.getErrorCode(), ex.getErrorCode().getCategory());
        assertEquals(ErrorCode.INVALID_PARAMETER, ex.getErrorCode());
    }

    @Test
    @DisplayName("Base64 非法归类为 MALFORMED_CIPHERTEXT(CIPHERTEXT)")
    void parseBadBase64() {
        String input = "!!!不是base64!!!";
        ApiException ex = assertThrows(ApiException.class, () -> EnvelopeCiphertext.parse(input));
        log.info("[关键输入] ciphertext={} -> code={}", input, ex.getErrorCode());
        assertEquals(ErrorCode.MALFORMED_CIPHERTEXT, ex.getErrorCode());
    }

    @Test
    @DisplayName("魔数错误归类为 MALFORMED_CIPHERTEXT(CIPHERTEXT)")
    void parseBadMagic() {
        byte[] raw = Base64.getDecoder().decode(validEnvelopeBase64());
        raw[0] = 'X';
        String input = Base64.getEncoder().encodeToString(raw);
        ApiException ex = assertThrows(ApiException.class, () -> EnvelopeCiphertext.parse(input));
        log.info("[关键输入] 篡改首字节魔数 -> code={}, message={}", ex.getErrorCode(), ex.getMessage());
        assertEquals(ErrorCode.MALFORMED_CIPHERTEXT, ex.getErrorCode());
    }

    @Test
    @DisplayName("密文被截断归类为 CIPHERTEXT_TRUNCATED(CIPHERTEXT)")
    void parseTruncated() {
        String valid = validEnvelopeBase64();
        String truncated = valid.substring(0, valid.length() - 8);
        ApiException ex = assertThrows(ApiException.class, () -> EnvelopeCiphertext.parse(truncated));
        log.info("[关键输入] 截断密文 原始长度={} 截断后长度={} -> code={}, message={}",
                valid.length(), truncated.length(), ex.getErrorCode(), ex.getMessage());
        assertEquals(ErrorCode.CIPHERTEXT_TRUNCATED, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("负载密文"));
    }

    @Test
    @DisplayName("不同错误必须可区分：MALFORMED 与 TRUNCATED 不是同一错误码")
    void errorCodesAreDistinct() {
        ApiException badMagic = assertThrows(ApiException.class,
                () -> EnvelopeCiphertext.parse(Base64.getEncoder().encodeToString(new byte[]{'X', 'K', 'M', '1', 1})));
        ApiException truncated = assertThrows(ApiException.class,
                () -> EnvelopeCiphertext.parse(Base64.getEncoder().encodeToString(new byte[]{'E', 'K', 'M', '1'})));
        log.info("[判定依据] badMagic={}({}) vs truncated={}({})",
                badMagic.getErrorCode(), badMagic.getErrorCode().getCategory(),
                truncated.getErrorCode(), truncated.getErrorCode().getCategory());
        assertEquals(ErrorCode.MALFORMED_CIPHERTEXT, badMagic.getErrorCode());
        assertEquals(ErrorCode.CIPHERTEXT_TRUNCATED, truncated.getErrorCode());
    }
}
