package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.key.LocalKeyStore;
import com.github.highcumontoa.envelopekeymanagementjava.key.MasterKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景测试：
 * 1) 重复/并发轮换不产生重复版本、不抛错；
 * 2) 轮换进行中并发加密/解密全部成功且全部可往返解回；
 * 3) 审计并发写入不丢记录。
 */
class ConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyTest.class);

    @TempDir
    Path tempDir;

    private LocalKeyStore keyStore;
    private KeyManagementService kms;
    private EnvelopeCryptoService crypto;

    @BeforeEach
    void setUp() throws Exception {
        keyStore = new LocalKeyStore(tempDir.resolve("keys"));
        invokeInit(keyStore);
        kms = new KeyManagementService(keyStore);
        crypto = new EnvelopeCryptoService(kms);
    }

    private static void invokeInit(Object bean) throws Exception {
        var m = bean.getClass().getDeclaredMethod("initialize");
        m.setAccessible(true);
        m.invoke(bean);
    }

    @Test
    @DisplayName("20 个线程并发轮换：版本严格递增且无重复、无丢失")
    void concurrentRotationsProduceUniqueVersions() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        Set<Integer> versions = ConcurrentHashMap.newKeySet();
        AtomicInteger errors = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    MasterKey key = kms.rotateMasterKey();
                    versions.add(key.getVersion());
                } catch (Exception e) {
                    errors.incrementAndGet();
                    log.error("轮换异常", e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发轮换未在时限内完成");
        pool.shutdown();

        log.info("[判定依据] 并发轮换 {} 次，产生版本集合={}，异常数={}", threads, versions, errors.get());
        assertEquals(0, errors.get(), "并发轮换不允许有失败");
        assertEquals(threads, versions.size(), "版本号不得重复");
        Set<Integer> expected = new HashSet<>();
        for (int v = 2; v <= threads + 1; v++) {
            expected.add(v);
        }
        assertEquals(expected, versions, "版本必须恰好是 2..N+1，既不重复也不缺失");
    }

    @Test
    @DisplayName("轮换进行中 12 个线程并发加密+解密：全部成功且密文都能往返")
    void concurrentEncryptDecryptDuringRotation() throws Exception {
        int encryptors = 8;
        int rotators = 4;
        int perEncryptor = 25;
        ExecutorService pool = Executors.newFixedThreadPool(encryptors + rotators);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();
        List<EnvelopeCryptoService.Encrypted> produced =
                java.util.Collections.synchronizedList(new ArrayList<>());

        for (int r = 0; r < rotators; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 10; i++) {
                        kms.rotateMasterKey();
                    }
                } catch (Exception e) {
                    failures.incrementAndGet();
                }
            });
        }
        for (int e = 0; e < encryptors; e++) {
            final int worker = e;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perEncryptor; i++) {
                        String plaintext = "worker-" + worker + "-msg-" + i;
                        EnvelopeCryptoService.Encrypted enc = crypto.encrypt(plaintext);
                        // 立即解密，验证轮换中间态不影响任何请求
                        String back = crypto.decrypt(enc.ciphertext());
                        if (!plaintext.equals(back)) {
                            failures.incrementAndGet();
                        }
                        produced.add(enc);
                    }
                } catch (Exception ex) {
                    failures.incrementAndGet();
                    log.error("轮换期间加解密异常", ex);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        log.info("[判定依据] 轮换期间产生密文 {} 条，当前 KEK 版本={}，失败数={}",
                produced.size(), kms.currentMasterKey().getVersion(), failures.get());
        assertEquals(0, failures.get(), "轮换期间不允许加解密失败或解出错误明文");

        // 全部轮换结束后，历史密文仍必须可解（覆盖多个 KEK 版本）
        Set<Integer> usedVersions = new HashSet<>();
        for (EnvelopeCryptoService.Encrypted enc : produced) {
            usedVersions.add(enc.masterKeyVersion());
            // 两次解密结果必须一致
            assertEquals(crypto.decrypt(enc.ciphertext()), crypto.decrypt(enc.ciphertext()));
        }
        log.info("[判定依据] 密文覆盖的 KEK 版本集合={}（应大于 1，证明跨版本一致）", usedVersions);
        assertTrue(usedVersions.size() > 1, "并发加密应跨越至少两个主密钥版本");
    }

    @Test
    @DisplayName("500 条并发审计写入：记录无丢失、序号唯一且连续")
    void concurrentAuditWrites() throws Exception {
        AuditService audit = new AuditService(tempDir.resolve("audit"));
        invokeInit(audit);
        int threads = 10;
        int perThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final int worker = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        audit.record("caller-" + (worker % 3), AuditAction.ENCRYPT,
                                AuditEvent.RESULT_SUCCESS, "worker=" + worker + ",i=" + i);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        var all = audit.query(null, null);
        long distinctIds = all.stream().map(AuditEvent::id).distinct().count();
        log.info("[判定依据] 期望审计记录 {}，实际 {}，唯一序号数 {}",
                threads * perThread, all.size(), distinctIds);
        assertEquals(threads * perThread, all.size());
        assertEquals(threads * perThread, distinctIds);
        // ACCESS_DENIED 的空查询之外，文件行数也应一致
        long fileLines = java.nio.file.Files.readString(
                tempDir.resolve("audit").resolve(AuditService.AUDIT_FILE_NAME))
                .lines().filter(l -> !l.isBlank()).count();
        assertEquals(threads * perThread, fileLines, "审计文件行数必须与内存记录一致（不丢记录）");
    }
}
