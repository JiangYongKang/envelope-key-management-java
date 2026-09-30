package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRotationTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationTest.class);

    @TempDir
    Path tempDir;
    private TestStack stack;

    @BeforeEach
    void setUp() {
        stack = TestStack.create(tempDir);
    }

    @Test
    void newDataUsesNewVersionAfterRotationWhileOldCiphertextStillDecrypts() {
        // 轮换前用 v1 加密
        String oldPlaintext = "before-rotation-旧数据";
        String oldCipher = stack.encryption().encrypt("svc-dec", oldPlaintext);
        int versionBefore = stack.kms().currentMasterKey().version();
        assertEquals(1, versionBefore);
        log.info("关键输入: 轮换前明文='{}'，密文引用 v{}", oldPlaintext, versionBefore);

        // 执行轮换
        var rotated = stack.kms().rotateMasterKey();
        assertEquals(2, rotated.version().version());
        assertEquals(false, rotated.coalesced(), "首个轮换请求不应是合批");
        assertNotEquals(
                stack.masterKeyStore().findVersion(1).masterKey(),
                stack.masterKeyStore().findVersion(2).masterKey(),
                "新旧主密钥材料必须不同");
        log.info("轮换成功: 当前主密钥版本 v{}，历史版本保留 {}",
                rotated.version().version(),
                stack.kms().listMasterVersions().stream().map(KeyVersion::version).toList());

        // 轮换后新密文必须使用 v2
        String newPlaintext = "after-rotation-新数据";
        String newCipher = stack.encryption().encrypt("svc-dec", newPlaintext);
        int referencedVersion = stack.codec().parse(newCipher).masterVersion();
        assertEquals(2, referencedVersion, "轮换后新数据必须用新版本密钥");
        log.info("关键输入: 轮换后明文='{}'，新密文引用 v{}（判定: 使用新版本）",
                newPlaintext, referencedVersion);

        // 历史密文仍能用旧版本正确解密
        assertEquals(oldPlaintext, stack.encryption().decrypt("svc-dec", oldCipher));
        // 新密文也能解
        assertEquals(newPlaintext, stack.encryption().decrypt("svc-dec", newCipher));
        log.info("[判定] 旧密文以 v1 解密成功，新密文以 v2 解密成功（向后兼容）");

        // 再次轮换 -> v3，严格单调
        assertEquals(3, stack.kms().rotateMasterKey().version().version());
        assertEquals(3, stack.kms().currentMasterKey().version());

        // 审计中应能查到轮换记录（带时间和操作类型）
        long rotateEvents = stack.auditService().query(null, AuditAction.ROTATE).size();
        assertTrue(rotateEvents >= 2, "每次轮换都应留审计，实际 " + rotateEvents);
        log.info("[判定] 审计中 ROTATE 记录数={}", rotateEvents);
    }
}
