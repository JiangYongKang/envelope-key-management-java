package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvelopeEncryptionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeEncryptionServiceTest.class);

    @TempDir
    Path tempDir;

    private TestStack stack;

    @BeforeEach
    void setUp() {
        stack = TestStack.create(tempDir);
    }

    @Test
    void samePlaintextProducesDifferentCiphertextButBothDecrypt() {
        String plaintext = "secret-payload-机密";
        String c1 = stack.encryption().encrypt("svc-dec", plaintext);
        String c2 = stack.encryption().encrypt("svc-dec", plaintext);
        log.info("关键输入: 明文='{}'", plaintext);
        log.info("密文#1={}", c1);
        log.info("密文#2={}", c2);
        assertNotEquals(c1, c2, "同一明文每次加密结果必须不同（随机 IV + 新 DEK）");

        assertEquals(plaintext, stack.encryption().decrypt("svc-dec", c1));
        assertEquals(plaintext, stack.encryption().decrypt("svc-dec", c2));
        log.info("[判定] 两条不同密文均正确解回原值");
    }

    @Test
    void rejectEmptyPlaintextAsInvalidParameter() {
        EnvelopeException ex = assertThrows(EnvelopeException.class,
                () -> stack.encryption().encrypt("svc-dec", ""));
        assertEquals(ErrorCode.INVALID_PARAMETER, ex.getCode());
        log.info("[判定] 空明文 => INVALID_PARAMETER，依据: {}", ex.getMessage());
    }

    @Test
    void rejectTruncatedCiphertextAsMalformed() {
        String c = stack.encryption().encrypt("svc-dec", "hello");
        String truncated = c.substring(0, c.length() - 8);
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", truncated),
                ErrorCode.CIPHERTEXT_MALFORMED, "密文尾部截断 8 字符");
    }

    @Test
    void rejectTamperedPayloadCiphertextAsTampered() {
        String c = stack.encryption().encrypt("svc-dec", "hello-tamper");
        // 翻转负载段（最后一段）的一个字符，保持段数与长度
        String tampered = flipLastSegmentChar(c);
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", tampered),
                ErrorCode.CIPHERTEXT_TAMPERED, "负载密文字节被翻转");
    }

    @Test
    void rejectTamperedWrappedDekAsTampered() {
        String c = stack.encryption().encrypt("svc-dec", "hello-wrap");
        String tampered = flipSegmentChar(c, 3); // 第 3 段 = wrappedDek
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", tampered),
                ErrorCode.CIPHERTEXT_TAMPERED, "被包裹 DEK 字节被翻转");
    }

    @Test
    void rejectReferenceToMissingMasterVersion() {
        String c = stack.encryption().encrypt("svc-dec", "version-missing");
        String changed = replaceVersion(c, 9999);
        // 版本 9999 不存在：应在查主密钥版本时明确报 KEY_VERSION_NOT_FOUND，
        // 而不是笼统地报篡改
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", changed),
                ErrorCode.KEY_VERSION_NOT_FOUND, "把版本引用改成不存在的 v9999");
    }

    @Test
    void rejectVersionSwitchedToExistingVersionAsTampered() {
        String c1 = stack.encryption().encrypt("svc-dec", "first");
        stack.kms().rotateMasterKey();
        String c2 = stack.encryption().encrypt("svc-dec", "second");
        // 把 c2 的版本从 v2 改成真实存在的 v1：版本查得到，但 AAD/标签不匹配 -> 篡改
        String switched = replaceVersion(c2, 1);
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", switched),
                ErrorCode.CIPHERTEXT_TAMPERED, "把版本引用改成另一个存在的版本 v1");
        // 原始密文依旧可解
        assertEquals("second", stack.encryption().decrypt("svc-dec", c2));
        assertEquals("first", stack.encryption().decrypt("svc-dec", c1));
    }

    @Test
    void rejectUnknownDataKeyAsDataKeyNotFound() {
        String c = stack.encryption().encrypt("svc-dec", "lost-key");
        String replaced = replaceKeyId(c, "00000000-0000-0000-0000-000000000000");
        assertErrorCode(() -> stack.encryption().decrypt("svc-dec", replaced),
                ErrorCode.DATA_KEY_NOT_FOUND, "把 keyId 改成不存在的值");
    }

    @Test
    void neverReturnsPlaintextOnAnyFailure() throws Exception {
        String plaintext = "never-leak";
        String c = stack.encryption().encrypt("svc-dec", plaintext);
        List<Runnable> attacks = List.of(
                () -> stack.encryption().decrypt("svc-dec", c.substring(0, c.length() - 5)),
                () -> stack.encryption().decrypt("svc-dec", flipLastSegmentChar(c)),
                () -> stack.encryption().decrypt("svc-dec", replaceVersion(c, 9999)),
                () -> stack.encryption().decrypt("svc-dec", replaceKeyId(c, "deadbeef")),
                () -> stack.encryption().decrypt("svc-dec", "garbage"),
                () -> stack.encryption().decrypt("svc-dec", null));
        for (Runnable attack : attacks) {
            assertThrows(EnvelopeException.class, attack::run,
                    "任何异常输入都必须抛业务异常而非返回明文");
        }
        log.info("[判定] 5 类异常输入全部被拒绝，无一路径返回明文");
    }

    private void assertErrorCode(org.junit.jupiter.api.function.Executable op,
                                 ErrorCode expected, String input) {
        EnvelopeException ex = assertThrows(EnvelopeException.class, op, input);
        // 把所有可区分错误码打印出来，便于核对分类
        log.info("[判定] 关键输入='{}' => {}，依据: {}", input, ex.getCode(), ex.getMessage());
        assertEquals(expected, ex.getCode(),
                "输入[" + input + "]错误分类错误: " + ex.getMessage());
        assertTrue(ex.getMessage() != null && !ex.getMessage().isBlank());
    }

    private static String[] split(String c) {
        return c.substring("EKM1:".length()).split("\\.", -1);
    }

    private static String join(String[] parts) {
        return "EKM1:" + String.join(".", parts);
    }

    private String flipLastSegmentChar(String c) {
        return flipSegmentChar(c, 5);
    }

    private static String flipSegmentChar(String c, int idx) {
        String[] p = split(c);
        char[] chars = p[idx].toCharArray();
        // 翻转首字符：它必然对应解码后的真实字节，避免改到 Base64 尾部填充位
        int pos = 0;
        chars[pos] = chars[pos] == 'A' ? 'B' : 'A';
        p[idx] = new String(chars);
        return join(p);
    }

    private static String replaceVersion(String c, int newVersion) {
        String[] p = split(c);
        p[0] = Integer.toString(newVersion);
        return join(p);
    }

    private static String replaceKeyId(String c, String newKeyId) {
        String[] p = split(c);
        p[1] = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(newKeyId.getBytes());
        return join(p);
    }
}
