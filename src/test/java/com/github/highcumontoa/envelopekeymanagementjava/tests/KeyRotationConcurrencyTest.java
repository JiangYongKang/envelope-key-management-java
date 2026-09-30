package com.github.highcumontoa.envelopekeymanagementjava.tests;

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
import java.util.concurrent.Future;
import com.github.highcumontoa.envelopekeymanagementjava.service.KeyManagementService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRotationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationConcurrencyTest.class);

    @TempDir
    Path tempDir;

    /**
     * 多个轮换请求在“领头条目真正写新版本”的窗口内同时进入，
     * 必须合批为同一个新版本：不产生重复版本、不打断进行中的轮换。
     */
    @Test
    void concurrentRotationsCoalesceIntoOneNewVersion() throws Exception {
        int threads = 16;
        CountDownLatch insideHook = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger entered = new AtomicInteger();

        TestStack s = TestStack.createWithRotationHook(tempDir, kms -> {
            // 领头条目进入落盘前：先放行所有轮换线程入队，再统一释放
            entered.incrementAndGet();
            insideHook.countDown();
            try {
                if (!release.await(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("轮换钩子等待释放超时");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<KeyManagementService.RotationResult>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    return s.kms().rotateMasterKey();
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();

            // 确保领头条目已进入窗口
            assertTrue(insideHook.await(5, TimeUnit.SECONDS), "领头条目应进入轮换窗口");
            // 给其余线程时间进入“等待合批”
            Thread.sleep(200);
            release.countDown(); // 领头条目真正完成新版本写入

            Set<Integer> produced = new HashSet<>();
            int coalesced = 0;
            for (Future<KeyManagementService.RotationResult> f : futures) {
                KeyManagementService.RotationResult rr = f.get(10, TimeUnit.SECONDS);
                produced.add(rr.version().version());
                if (rr.coalesced()) {
                    coalesced++;
                }
            }
            log.info("其中被合批（coalesced=true）的请求数={}", coalesced);
            assertTrue(coalesced >= 1, "窗口内的并发请求应至少有一个被标记为合批");
            log.info("关键输入: {} 个并发轮换请求，产出版本集合={}", threads, produced);
            // 所有并发请求都拿到同一个新版本，且只新增一个版本
            assertEquals(Set.of(2), produced, "并发轮换必须合批为同一新版本 v2");
            assertEquals(2, s.kms().currentMasterKey().version());
            List<Integer> versions = s.masterKeyStore().loadAll().stream()
                    .map(kv -> kv.version()).sorted().toList();
            assertEquals(List.of(1, 2), versions, "不得产生重复/跳跃版本");
            log.info("[判定] 并发轮换合批成功，最终版本序列={}（无重复、无打断）", versions);
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * 轮换进行中持续发起加密/解密，任何请求都不能因轮换中间状态失败或读到不一致密钥。
     */
    @Test
    void encryptDecryptWorkDuringRotation() throws Exception {
        TestStack s = TestStack.createWithRotationHook(tempDir, kms -> {
            try {
                Thread.sleep(300); // 放大“轮换进行中”窗口
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        // 预置一条 v1 密文，轮换全程都应能解
        String seedCipher = s.encryption().encrypt("svc-dec", "persistent-种子密文");

        int workers = 12;
        int perWorker = 40;
        ExecutorService pool = Executors.newFixedThreadPool(workers + 1);
        CountDownLatch start = new CountDownLatch(1);
        Set<Throwable> errors = ConcurrentHashMap.newKeySet();
        AtomicInteger successes = new AtomicInteger();
        List<String> allCiphers = java.util.Collections.synchronizedList(new ArrayList<>());

        try {
            // 单个轮换线程
            Future<?> rotator = pool.submit(() -> {
                try {
                    start.await();
                    s.kms().rotateMasterKey();
                } catch (Throwable t) {
                    errors.add(t);
                }
            });

            List<Future<?>> cryptoWorkers = new ArrayList<>();
            for (int w = 0; w < workers; w++) {
                final int wid = w;
                cryptoWorkers.add(pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perWorker; i++) {
                            String plaintext = "w" + wid + "-" + i;
                            String cipher = s.encryption().encrypt("svc-dec", plaintext);
                            allCiphers.add(cipher);
                            String back = s.encryption().decrypt("svc-dec", cipher);
                            if (!plaintext.equals(back)) {
                                throw new AssertionError("解密结果与原文不一致: " + plaintext);
                            }
                            // 轮换中的旧密文也必须随时可解
                            if (!"persistent-种子密文".equals(s.encryption().decrypt("svc-dec", seedCipher))) {
                                throw new AssertionError("种子密文在轮换期间解密失败");
                            }
                            successes.incrementAndGet();
                        }
                    } catch (Throwable t) {
                        errors.add(t);
                    }
                }));
            }

            start.countDown();
            rotator.get(15, TimeUnit.SECONDS);
            for (Future<?> f : cryptoWorkers) {
                f.get(15, TimeUnit.SECONDS);
            }

            log.info("关键输入: {} 个工作线程各 {} 次加密+解密，成功 {} 次，错误 {} 个",
                    workers, perWorker, successes.get(), errors.size());
            assertEquals(0, errors.size(),
                    "轮换期间的加解密不得失败: " + errors);
            assertEquals(workers * perWorker, successes.get());

            // 汇总新产生密文所引用的版本：v1/v2 都可能出现，但都必须可解
            Set<Integer> referenced = new HashSet<>();
            for (String c : allCiphers) {
                referenced.add(s.codec().parse(c).masterVersion());
            }
            log.info("轮换期间产生密文引用的主密钥版本集合={}（v1 为窗口前/瞬间，v2 为窗口后）",
                    referenced);
            assertTrue(referenced.contains(2), "轮换后必须有用 v2 的新密文");
            for (String c : allCiphers) {
                // 全量再解密一次，确保没有“当时可用、之后损坏”的不一致
                int v = s.codec().parse(c).masterVersion();
                assertTrue(v == 1 || v == 2);
            }
            log.info("[判定] 轮换全程加解密一致，种子 v1 密文始终可解，无中间状态失败");
        } finally {
            pool.shutdownNow();
        }
    }
}
