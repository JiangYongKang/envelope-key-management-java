package com.github.highcumontoa.envelopekeymanagementjava.audit;

import java.time.Instant;

/** 一条审计记录：时间、调用方、操作类型、结果、目标、详情。 */
public record AuditEvent(String eventId,
                         Instant timestamp,
                         String callerId,
                         AuditAction action,
                         boolean success,
                         String target,
                         String detail) {
}
