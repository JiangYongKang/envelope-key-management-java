package com.github.highcumontoa.envelopekeymanagementjava.audit;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 审计服务：所有密钥使用、轮换与被拒绝请求都留下可查询记录。
 *
 * <p>写入串行化（同一把锁 + 单行 append），配合单调递增序号，保证并发写入下
 * 记录不丢失、不交错。查询只读内存副本，支持按调用方/操作类型过滤；
 * 同时每行以 TSV 追加到 {@code local-data/audit.log}，重启后可追溯。</p>
 */
@Component
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    public static final String AUDIT_FILE_NAME = "audit.log";

    private final Path dataDir;
    private final Path auditFile;
    private final AtomicLong sequence = new AtomicLong(0);
    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final Object writeLock = new Object();

    @org.springframework.beans.factory.annotation.Autowired
    public AuditService(@Value("${ekm.local.dir:./local-data}") String dataDir) {
        this(Path.of(dataDir));
    }

    public AuditService(Path dataDir) {
        this.dataDir = dataDir;
        this.auditFile = dataDir.resolve(AUDIT_FILE_NAME);
    }

    @PostConstruct
    void initialize() {
        try {
            Files.createDirectories(dataDir);
            if (Files.notExists(auditFile)) {
                Files.createFile(auditFile);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("初始化审计文件失败: " + auditFile, e);
        }
    }

    /** 追加一条审计记录。null 的 callerId/detail 会被归一为空串，绝不抛 NPE。 */
    public AuditEvent record(String callerId, AuditAction action, String result, String detail) {
        long id = sequence.incrementAndGet();
        AuditEvent event = new AuditEvent(id, Instant.now(),
                callerId == null ? "" : callerId,
                action,
                result == null ? "" : result,
                detail == null ? "" : detail);
        synchronized (writeLock) {
            String line = event.id() + "\t" + event.timestamp() + "\t" + event.action()
                    + "\t" + event.result() + "\t" + event.callerId() + "\t"
                    + event.detail().replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                    + System.lineSeparator();
            try {
                Files.writeString(auditFile, line, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                // 审计落盘失败不能拖垮业务，但要让序号回退以免内存与文件出现空洞
                sequence.decrementAndGet();
                throw new UncheckedIOException("审计记录写入失败: " + auditFile, e);
            }
            events.add(event);
        }
        log.info("AUDIT #{} time={} caller={} action={} result={} detail={}",
                event.id(), event.timestamp(), event.callerId(),
                event.action(), event.result(), event.detail());
        return event;
    }

    /** 查询审计记录；两个过滤条件均可为 null 表示不过滤，结果按序号升序。 */
    public List<AuditEvent> query(String callerId, AuditAction action) {
        List<AuditEvent> filtered = events.stream()
                .filter(e -> callerId == null || callerId.isBlank() || callerId.equals(e.callerId()))
                .filter(e -> action == null || action == e.action())
                .collect(Collectors.toList());
        return Collections.unmodifiableList(filtered);
    }

    public long count() {
        return events.size();
    }
}
