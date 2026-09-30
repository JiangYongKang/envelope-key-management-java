package com.github.highcumontoa.envelopekeymanagementjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyVersion;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

/**
 * 主密钥版本的本地文件存储，用 JSON 文件模拟 KMS 中的主密钥保管。
 *
 * <p>持久化文件：{@code <dataDir>/master-keys.json}。写入采用
 * “写临时文件 + 原子 move”，避免轮换过程中其它线程读到半写文件。
 * 首次启动若文件不存在则引导生成 v1 主密钥。历史版本永不在轮换时删除，
 * 因此旧密文始终能找到对应版本解密。
 *
 * <p>所有公开方法均 synchronized，与本 JVM 内的读取互斥；运行期真正的
 * 权威状态是内存列表，文件保证重启后可恢复。
 */
public class MasterKeyStore {

    static final String FILE_NAME = "master-keys.json";

    private record PersistedKey(int version, String keyMaterialBase64, String createdAt, boolean enabled) {
    }

    private record PersistedFile(List<PersistedKey> keys) {
    }

    private final Path file;
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final List<KeyVersion> versions = new ArrayList<>();

    public MasterKeyStore(String dataDir) {
        Path dir = Path.of(dataDir);
        this.file = dir.resolve(FILE_NAME);
        try {
            Files.createDirectories(dir);
            bootstrap();
        } catch (IOException e) {
            throw new UncheckedIOException("初始化主密钥存储失败: " + dir, e);
        }
    }

    private void bootstrap() throws IOException {
        if (Files.exists(file)) {
            loadFromDisk();
        } else {
            // 首次启动引导 v1，密钥材料来自本地 SecureRandom，无任何外部依赖
            byte[] material = new CryptoService().generateRandomBytes(CryptoService.KEY_LENGTH_BYTES);
            versions.add(new KeyVersion(1, material, Instant.now(), true));
            persist();
        }
    }

    private void loadFromDisk() throws IOException {
        byte[] raw = Files.readAllBytes(file);
        try {
            PersistedFile persisted = mapper.readValue(raw, PersistedFile.class);
            versions.clear();
            if (persisted.keys() != null) {
                for (PersistedKey k : persisted.keys()) {
                    versions.add(new KeyVersion(
                            k.version(),
                            Base64.getDecoder().decode(k.keyMaterialBase64()),
                            Instant.parse(k.createdAt()),
                            k.enabled()));
                }
            }
            if (versions.isEmpty()) {
                throw new IOException("主密钥文件中没有任何密钥版本");
            }
        } catch (Exception e) {
            throw new IOException("解析主密钥文件失败: " + file, e);
        }
    }

    public synchronized List<KeyVersion> loadAll() {
        return List.copyOf(versions);
    }

    public synchronized KeyVersion current() {
        return versions.stream()
                .filter(KeyVersion::enabled)
                .max(Comparator.comparingInt(KeyVersion::version))
                .orElseThrow();
    }

    /** 按版本号查找；不存在返回 null（由上层转成 KEY_VERSION_NOT_FOUND）。 */
    public synchronized KeyVersion findVersion(int version) {
        return versions.stream()
                .filter(kv -> kv.version() == version)
                .findFirst()
                .orElse(null);
    }

    public synchronized int currentVersionNumber() {
        return current().version();
    }

    /**
     * 追加新版本。版本号由当前最大号 +1 决定，绝不复用。
     * 调用方需自行做跨调用去重（见 KeyManagementService 的轮换合批）。
     */
    public synchronized KeyVersion append(byte[] keyMaterial) {
        int next = versions.stream().mapToInt(KeyVersion::version).max().orElse(0) + 1;
        KeyVersion kv = new KeyVersion(next, keyMaterial.clone(), Instant.now(), true);
        versions.add(kv);
        try {
            persist();
        } catch (IOException e) {
            versions.remove(kv);
            throw new UncheckedIOException("写入主密钥文件失败", e);
        }
        return kv;
    }

    private void persist() throws IOException {
        List<PersistedKey> dto = versions.stream()
                .map(kv -> new PersistedKey(
                        kv.version(),
                        Base64.getEncoder().encodeToString(kv.masterKey()),
                        kv.createdAt().toString(),
                        kv.enabled()))
                .toList();
        Path tmp = file.resolveSibling(FILE_NAME + ".tmp");
        Files.writeString(tmp, mapper.writeValueAsString(new PersistedFile(dto)), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** 供需要显式错误的场景使用的安全查找。 */
    public synchronized KeyVersion requireVersion(int version) {
        KeyVersion kv = findVersion(version);
        if (kv == null || !kv.enabled()) {
            throw new EnvelopeException(ErrorCode.KEY_VERSION_NOT_FOUND,
                    "主密钥版本不存在或已停用: v" + version);
        }
        return kv;
    }
}
