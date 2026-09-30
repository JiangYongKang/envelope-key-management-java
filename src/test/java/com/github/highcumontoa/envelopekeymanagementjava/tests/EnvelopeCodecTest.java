package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCodec;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeParts;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvelopeCodecTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCodecTest.class);
    private final CryptoService crypto = new CryptoService();
    private final EnvelopeCodec codec = new EnvelopeCodec(crypto);

    private EnvelopeParts sampleParts() {
        return new EnvelopeParts(
                "key-123",
                7,
                crypto.generateRandomBytes(12),
                crypto.generateRandomBytes(32), // 16 标签 + 16 数据
                crypto.generateRandomBytes(12),
                crypto.generateRandomBytes(48));
    }

    @Test
    void encodeThenParseRoundTrip() {
        EnvelopeParts in = sampleParts();
        String encoded = codec.encode(in);
        log.info("输入 keyId={}, version={}，密文样例={}", in.keyId(), in.masterVersion(),
                encoded.substring(0, Math.min(60, encoded.length())) + "...");
        EnvelopeParts out = codec.parse(encoded);
        assertEquals(in.keyId(), out.keyId());
        assertEquals(in.masterVersion(), out.masterVersion());
        assertEquals(7, out.masterVersion());
    }

    @Test
    void rejectMalformedInputs() {
        assertMalformed(null, "空密文");
        assertMalformed("", "空白密文");
        assertMalformed("XXXX:1.a.b.c.d.e", "错误前缀");
        assertMalformed("EKM1:1.a.b.c.d", "段数不足（截断）");
        assertMalformed("EKM1:abc.a.b.c.d.e", "版本号非数字");
        assertMalformed("EKM1:0.a.b.c.d.e", "版本号为 0");
        // Base64 段被截断
        String good = codec.encode(sampleParts());
        assertMalformed(good.substring(0, good.length() - 3), "尾部被截断 3 字符");
        // 构造长度非法：payloadIv 只有 4 字节
        B64 b = new B64();
        String badIv = "EKM1:7." + b.s("key") + "." + b.bin(12) + "." + b.bin(32)
                + "." + b.bin(4) + "." + b.bin(48);
        assertMalformed(badIv, "payloadIv 长度非法");
    }

    private void assertMalformed(String ciphertext, String desc) {
        EnvelopeException ex = assertThrows(EnvelopeException.class,
                () -> codec.parse(ciphertext), desc);
        assertEquals(ErrorCode.CIPHERTEXT_MALFORMED, ex.getCode(),
                "[" + desc + "] 应归类为 CIPHERTEXT_MALFORMED");
        log.info("[判定] 输入='{}' => CIPHERTEXT_MALFORMED，依据: {}",
                desc, ex.getMessage());
        assertTrue(ex.getMessage().length() > 0);
    }

    private static final class B64 {
        private final Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();

        String s(String s) {
            return e.encodeToString(s.getBytes());
        }

        String bin(int n) {
            byte[] bytes = new byte[n];
            return e.encodeToString(bytes);
        }
    }
}
