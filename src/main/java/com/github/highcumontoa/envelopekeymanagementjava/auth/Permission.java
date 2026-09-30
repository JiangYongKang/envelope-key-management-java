package com.github.highcumontoa.envelopekeymanagementjava.auth;

/**
 * 调用方可被授予的操作权限。
 */
public enum Permission {
    /** 加密（POST /api/v1/encrypt）。 */
    ENCRYPT,
    /** 解密（POST /api/v1/decrypt）。 */
    DECRYPT,
    /** 主密钥轮换（POST /api/v1/keys/rotate）。 */
    ROTATE,
    /** 查询审计记录（GET /api/v1/audit）。 */
    AUDIT_READ
}
