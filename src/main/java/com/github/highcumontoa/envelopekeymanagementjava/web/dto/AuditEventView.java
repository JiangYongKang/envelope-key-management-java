package com.github.highcumontoa.envelopekeymanagementjava.web.dto;

import java.time.Instant;

public record AuditEventView(String eventId,
                             Instant timestamp,
                             String callerId,
                             String action,
                             boolean success,
                             String target,
                             String detail) {
}
