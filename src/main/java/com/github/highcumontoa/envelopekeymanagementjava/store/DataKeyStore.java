package com.github.highcumontoa.envelopekeymanagementjava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.envelopekeymanagementjava.key.DataKey;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 数据密钥（DEK）的本地文件存储。
 *
 * <p>持久化文件：{@code <dataDir>/data-keys.json}，以 keyId 为主键。
 * 存盘的 DEK 永远是“被主密钥包裹”的形态，明文 DEK 只在单次请求内存在。
 * 写入同样走临时文件 + 原子 move，保证并发轮换/加密过程中读到的文件始终完整。
 */
public class DataKeyStore {

    static final String FILE_NAME = "data-keys.json";

    private record PersistedDataKey(String keyId,
                                    int masterVersion,
                                    String wrappedKeyBase64,
                                    String wrappingIvBase64,
                                    String createdAt,
                                    boolean enabled) {
    }

    private final Path file;
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final Map<String, DataKey> byId = new LinkedHashMap<>();

    public DataKeyStore(String dataDir) {
        Path dir = Path.of(dataDir);
        this.file = dir.resolve(FILE_NAME);
        try {
            Files.createDirectories(dir);
            if (Files.exists(file)) {
                loadFromDisk();
            } else {
                persist();
            }
        } catch (IOException e) {
            throw new UncheckedIOException("初始化数据密钥存储失败: " + dir, e);
        }
    }

    private void loadFromDisk() throws IOException {
        try {
            byte[] raw = Files.readAllBytes(file);
            List<PersistedDataKey> list = mapper.readValue(raw, new TypeReference<>() {
            });
            byId.clear();
            if (list != null) {
                for (PersistedDataKey p : list) {
                    byId.put(p.keyId(), new DataKey(
                            p.keyId(),
                            p.masterVersion(),
                            Base64.getDecoder().decode(p.wrappedKeyBase64()),
                            Base64.getDecoder().decode(p.wrappingIvBase64()),
                            Instant.parse(p.createdAt()),
                            p.enabled()));
                }
            }
        } catch (Exception e) {
            throw new IOException("解析数据密钥文件失败: " + file, e);
        }
    }

    public synchronized void put(DataKey dataKey) {
        if (dataKey == null || dataKey.keyId() == null) {
            throw new IllegalArgumentException("数据密钥及其 keyId 不能为空");
        }
        byId.put(dataKey.keyId(), dataKey);
        try {
            persist();
        } catch (IOException e) {
            byId.remove(dataKey.keyId());
            throw new UncheckedIOException("写入数据密钥文件失败", e);
        }
    }

    /** 不存在返回 null（由上层转成 DATA_KEY_NOT_FOUND）。 */
    public synchronized DataKey get(String keyId) {
        DataKey dk = byId.get(keyId);
        if (dk == null || !dk.enabled()) {
            return null;
        }
        return dk;
    }

    public synchronized List<DataKey> all() {
        return List.copyOf(byId.values());
    }

    private void persist() throws IOException {
        List<PersistedDataKey> list = new ArrayList<>();
        for (DataKey dk : byId.values()) {
            list.add(new PersistedDataKey(
                    dk.keyId(),
                    dk.masterVersion(),
                    Base64.getEncoder().encodeToString(dk.wrappedKey()),
                    Base64.getEncoder().encodeToString(dk.wrappingIv()),
                    dk.createdAt().toString(),
                    dk.enabled()));
        }
        Path tmp = file.resolveSibling(FILE_NAME + ".tmp");
        Files.writeString(tmp, mapper.writeValueAsString(list), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
