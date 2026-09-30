package com.github.highcumontoa.envelopekeymanagementjava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 审计记录的本地追加存储（{@code <dataDir>/audit-log.json}，JSON 数组）。
 *
 * <p>并发不丢的保证：{@link #append(AuditEvent)} 为 synchronized，
 * “加入内存列表 + 全量序列化 + 原子替换文件”在同一把监视器锁内一次完成，
 * 因此多线程同时记录时严格串行，每条事件都会落进最终文件。读取返回快照拷贝。
 */
public class AuditStore {

    static final String FILE_NAME = "audit-log.json";

    private final Path file;
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final List<AuditEvent> events = new ArrayList<>();

    public AuditStore(String dataDir) {
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
            throw new UncheckedIOException("初始化审计存储失败: " + dir, e);
        }
    }

    private void loadFromDisk() throws IOException {
        try {
            byte[] raw = Files.readAllBytes(file);
            List<AuditEvent> loaded = mapper.readValue(raw, new TypeReference<>() {
            });
            events.clear();
            if (loaded != null) {
                events.addAll(loaded);
            }
        } catch (Exception e) {
            throw new IOException("解析审计文件失败: " + file, e);
        }
    }

    /** 串行化追加，保证并发写入一条不丢。 */
    public synchronized void append(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("审计事件不能为空");
        }
        events.add(event);
        try {
            persist();
        } catch (IOException e) {
            // 落盘失败时回滚内存，保持内存与文件一致；错误向上传播以便请求方感知
            events.remove(events.size() - 1);
            throw new UncheckedIOException("写入审计文件失败", e);
        }
    }

    public synchronized List<AuditEvent> loadAll() {
        return List.copyOf(events);
    }

    private void persist() throws IOException {
        Path tmp = file.resolveSibling(FILE_NAME + ".tmp");
        Files.writeString(tmp, mapper.writeValueAsString(events), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
