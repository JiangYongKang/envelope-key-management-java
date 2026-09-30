package com.github.highcumontoa.envelopekeymanagementjava.audit;

import com.github.highcumontoa.envelopekeymanagementjava.store.AuditStore;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** 审计门面：写入（含时间戳与操作类型）与条件查询。 */
public class AuditService {

    private final AuditStore auditStore;

    public AuditService(AuditStore auditStore) {
        this.auditStore = auditStore;
    }

    /**
     * 记录一条审计。无论业务成功还是失败都可调用；
     * 时间戳取记录瞬间，事件 ID 全局唯一。
     */
    public AuditEvent record(String callerId, AuditAction action, boolean success,
                             String target, String detail) {
        AuditEvent event = new AuditEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                callerId == null ? "<未知>" : callerId,
                action,
                success,
                target == null ? "-" : target,
                detail == null ? "" : detail);
        auditStore.append(event);
        return event;
    }

    /**
     * 查询审计记录。callerId 或 action 为 null 时该维度不过滤。
     * 返回按时间先后排列的快照。
     */
    public List<AuditEvent> query(String callerId, AuditAction action) {
        return auditStore.loadAll().stream()
                .filter(e -> callerId == null || callerId.equals(e.callerId()))
                .filter(e -> action == null || action == e.action())
                .toList();
    }
}
