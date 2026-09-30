package com.github.highcumontoa.envelopekeymanagementjava.audit;

/** 审计操作类型。 */
public enum AuditAction {
    ENCRYPT,
    DECRYPT,
    ROTATE,
    GENERATE_DATA_KEY,
    AUDIT_QUERY,
    ACCESS_DENIED
}
