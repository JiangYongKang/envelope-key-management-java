package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Caller;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Permission;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.service.AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationAuditTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAuditTest.class);

    @TempDir
    Path tempDir;
    private TestStack stack;
    private AuthorizationService authz;

    @BeforeEach
    void setUp() {
        stack = TestStack.create(tempDir);
        authz = new AuthorizationService(stack.callerDirectory(), stack.auditService());
    }

    @Test
    void allowCallerWithPermission() {
        Caller admin = authz.requireCaller("key-admin");
        authz.requirePermission(admin.id(), Permission.ROTATE);
        log.info("[判定] key-admin 拥有 ROTATE，放行；权限集={}", admin.permissions());
    }

    @Test
    void denyUnknownCallerDistinctFromMissingPermission() {
        // 未知/缺失身份
        EnvelopeException unknown = assertThrows(EnvelopeException.class,
                () -> authz.requirePermission("ghost", Permission.ENCRYPT));
        assertEquals(ErrorCode.ACCESS_DENIED, unknown.getCode());
        assertTrue(unknown.getMessage().contains("身份未知"), unknown.getMessage());
        log.info("[判定] 未知调用方 ghost => ACCESS_DENIED，依据: {}", unknown.getMessage());

        EnvelopeException absent = assertThrows(EnvelopeException.class,
                () -> authz.requirePermission(null, Permission.ENCRYPT));
        assertEquals(ErrorCode.ACCESS_DENIED, absent.getCode());
        assertTrue(absent.getMessage().contains("未提供"), absent.getMessage());
        log.info("[判定] 缺失 X-Caller-Id => ACCESS_DENIED，依据: {}", absent.getMessage());

        // 已知但权限不足：错误码相同，原因文本明确不同
        EnvelopeException noPerm = assertThrows(EnvelopeException.class,
                () -> authz.requirePermission("svc-enc", Permission.DECRYPT));
        assertEquals(ErrorCode.ACCESS_DENIED, noPerm.getCode());
        assertTrue(noPerm.getMessage().contains("缺少权限") && noPerm.getMessage().contains("DECRYPT"),
                noPerm.getMessage());
        log.info("[判定] svc-enc 尝试 DECRYPT => ACCESS_DENIED，依据: {}", noPerm.getMessage());
    }

    @Test
    void deniedRequestsLeaveAuditTrail() {
        assertThrows(EnvelopeException.class,
                () -> authz.requirePermission("svc-limited", Permission.ENCRYPT));
        assertThrows(EnvelopeException.class,
                () -> authz.requirePermission("auditor", Permission.ROTATE));
        assertThrows(EnvelopeException.class,
                () -> authz.requirePermission("nobody", Permission.ENCRYPT));

        List<AuditEvent> denied = stack.auditService().query(null, AuditAction.ACCESS_DENIED);
        log.info("关键输入: 3 次越权；实际 ACCESS_DENIED 审计数={}", denied.size());
        assertEquals(3, denied.size(), "每次被拒绝都必须留审计");
        for (AuditEvent e : denied) {
            assertNotNull(e.timestamp());
            assertEquals(AuditAction.ACCESS_DENIED, e.action());
            assertEquals(false, e.success());
        }
        log.info("[判定] 拒绝记录均带时间戳/操作类型/结果=false，详情示例='{}'",
                denied.get(0).detail());
    }

    @Test
    void keyUsageAndRotationAreAudited() {
        stack.encryption().encrypt("svc-dec", "audit-me");
        String c = stack.encryption().encrypt("svc-dec", "audit-me-2");
        stack.encryption().decrypt("svc-dec", c);
        stack.kms().rotateMasterKey();

        assertEquals(2, stack.auditService().query(null, AuditAction.ENCRYPT).size());
        assertEquals(1, stack.auditService().query(null, AuditAction.DECRYPT).size());
        assertTrue(stack.auditService().query(null, AuditAction.ROTATE).size() >= 1);
        log.info("[判定] 加密2、解密1、轮换>=1 均有审计，全部含时间与操作类型");
    }

    @Test
    void concurrentAuditWritesLoseNoRecord() throws Exception {
        int threads = 20;
        int perThread = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        AtomicInteger counter = new AtomicInteger();
        try {
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perThread; i++) {
                            int n = counter.incrementAndGet();
                            stack.auditService().record("writer-" + (n % 5),
                                    AuditAction.ENCRYPT, true, "k" + n, "并发审计写入 #" + n);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }));
            }
            start.countDown();
            for (var f : futures) {
                f.get(15, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        // 基线审计（启动/前置可能为 0）+ 本次并发写入
        int expected = threads * perThread;
        long found = stack.auditService().query(null, AuditAction.ENCRYPT)
                .stream().filter(e -> e.detail().startsWith("并发审计写入")).count();
        log.info("关键输入: {} 线程 x {} = {} 条并发审计，实际落盘 {} 条",
                threads, perThread, expected, found);
        assertEquals(expected, found, "并发写入不得丢任何审计记录");

        // 重新从磁盘加载，验证文件层面也一条不丢
        com.github.highcumontoa.envelopekeymanagementjava.store.AuditStore reloaded =
                new com.github.highcumontoa.envelopekeymanagementjava.store.AuditStore(tempDir.toString());
        long onDisk = reloaded.loadAll().stream()
                .filter(e -> e.detail().startsWith("并发审计写入")).count();
        assertEquals(expected, onDisk, "持久化文件中审计记录必须完整");
        log.info("[判定] 内存与磁盘审计记录均为 {}，并发写入零丢失", onDisk);
    }
}
