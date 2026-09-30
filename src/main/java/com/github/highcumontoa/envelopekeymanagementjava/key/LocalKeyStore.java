package com.github.highcumontoa.envelopekeymanagementjava.key;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * 本地主密钥（KEK）存储，用文件模拟 HSM/KMS 的持久化。
 *
 * <p>存储格式为 properties 文本（{@code local-data/keys.properties}）：</p>
 * <pre>
 * current.version=2
 * key.1.createdAt=2026-09-30T10:00:00Z
 * key.1.material=base64(AES-256 原始密钥)
 * key.2.createdAt=...
 * key.2.material=...
 * </pre>
 *
 * <p>所有读写方法都加锁，写盘采用“临时文件 + 原子移动”，
 * 并发轮换只会产生严格递增、互不重复的版本，任何读操作都不会看到写一半的文件。</p>
 */
@Component
public class LocalKeyStore {

    private static final Logger log = LoggerFactory.getLogger(LocalKeyStore.class);

    static final String STORE_FILE_NAME = "keys.properties";
    private static final int AES_KEY_BITS = 256;

    private final Path dataDir;
    private final Path storeFile;
    private final SecureRandom secureRandom = new SecureRandom();

    /** version -> 主密钥，TreeMap 保证按版本有序。 */
    private final TreeMap<Integer, MasterKey> keysByVersion = new TreeMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public LocalKeyStore(@Value("${ekm.local.dir:./local-data}") String dataDir) {
        this(Path.of(dataDir));
    }

    public LocalKeyStore(Path dataDir) {
        this.dataDir = dataDir;
        this.storeFile = dataDir.resolve(STORE_FILE_NAME);
    }

    @PostConstruct
    synchronized void initialize() {
        try {
            if (Files.exists(storeFile)) {
                loadFromDisk();
            }
            if (keysByVersion.isEmpty()) {
                log.info("本地主密钥存储为空，生成首个主密钥 version=1 dir={}", dataDir);
                MasterKey first = generateMasterKey(1);
                keysByVersion.put(1, first);
                persist();
            } else {
                log.info("已加载本地主密钥版本={}", keysByVersion.keySet());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("初始化本地主密钥存储失败: " + storeFile, e);
        }
    }

    /** 返回当前（版本号最大的）主密钥。 */
    public synchronized MasterKey current() {
        return keysByVersion.lastEntry().getValue();
    }

    /** 按版本查找主密钥；不存在返回 {@code null}（由上层转换为 KEY_VERSION_NOT_FOUND）。 */
    public synchronized MasterKey findByVersion(int version) {
        return keysByVersion.get(version);
    }

    /** 返回全部历史主密钥（按版本升序的副本）。 */
    public synchronized List<MasterKey> all() {
        return new ArrayList<>(keysByVersion.values());
    }

    /**
     * 生成新版本主密钥并持久化。方法级锁保证并发/重复轮换调用得到的是不同的、
     * 严格递增的版本，且不会互相打断。
     */
    public synchronized MasterKey rotate() {
        int newVersion = keysByVersion.isEmpty() ? 1 : keysByVersion.lastKey() + 1;
        MasterKey key = generateMasterKey(newVersion);
        keysByVersion.put(newVersion, key);
        try {
            persist();
        } catch (IOException e) {
            // 写盘失败则回滚内存状态，避免内存与文件不一致
            keysByVersion.remove(newVersion);
            throw new UncheckedIOException("持久化新主密钥失败 version=" + newVersion, e);
        }
        log.info("主密钥轮换完成 newVersion={} 历史版本数={}", newVersion, keysByVersion.size());
        return key;
    }

    private MasterKey generateMasterKey(int version) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(AES_KEY_BITS, secureRandom);
            byte[] raw = generator.generateKey().getEncoded();
            return new MasterKey(version, raw, Instant.now());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JRE 不支持 AES", e);
        }
    }

    private void loadFromDisk() throws IOException {
        Properties props = new Properties();
        try (var in = Files.newBufferedReader(storeFile, StandardCharsets.UTF_8)) {
            props.load(in);
        }
        TreeMap<Integer, MasterKey> loaded = new TreeMap<>();
        for (String name : props.stringPropertyNames()) {
            if (name.startsWith("key.") && name.endsWith(".material")) {
                int version = Integer.parseInt(name.substring(4, name.length() - ".material".length()));
                byte[] material = Base64.getDecoder().decode(props.getProperty(name));
                Instant createdAt = Instant.parse(props.getProperty("key." + version + ".createdAt"));
                loaded.put(version, new MasterKey(version, material, createdAt));
            }
        }
        keysByVersion.clear();
        keysByVersion.putAll(loaded);
    }

    /** 全量写临时文件后原子替换，保证读侧永远看不到半截文件。 */
    private void persist() throws IOException {
        Files.createDirectories(dataDir);
        Properties props = new Properties();
        props.setProperty("current.version", String.valueOf(keysByVersion.lastKey()));
        for (Map.Entry<Integer, MasterKey> entry : keysByVersion.entrySet()) {
            MasterKey key = entry.getValue();
            props.setProperty("key." + key.getVersion() + ".createdAt", key.getCreatedAt().toString());
            props.setProperty("key." + key.getVersion() + ".material",
                    Base64.getEncoder().encodeToString(key.getRawKey()));
        }
        Path tmp = dataDir.resolve(STORE_FILE_NAME + ".tmp");
        try (var out = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            props.store(out, "local envelope key master keys; do not edit while service is running");
        }
        try {
            Files.move(tmp, storeFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, storeFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
