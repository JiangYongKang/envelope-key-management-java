package com.github.highcumontoa.envelopekeymanagementjava.audit;

/**
 * 被审计的操作类型。
 */
public enum AuditAction {
    /** 使用当前主密钥产生信封密文。 */
    ENCRYPT,
    /** 解密信封密文（含旧版本主密钥解出的历史密文）。 */
    DECRYPT,
    /** 主密钥轮换。 */
    ROTATE,
    /** 被拒绝的请求（参数/密钥类错误也会记录，方便追踪失败尝试）。 */
    REQUEST_REJECTED,
    /** 越权或未知调用方。 */
    ACCESS_DENIED
}
