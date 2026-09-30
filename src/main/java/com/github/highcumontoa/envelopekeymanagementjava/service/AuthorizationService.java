package com.github.highcumontoa.envelopekeymanagementjava.service;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Caller;
import com.github.highcumontoa.envelopekeymanagementjava.auth.CallerDirectory;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Permission;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;

/**
 * 鉴权：解析调用方并校验权限。
 *
 * <p>拒绝原因可区分（错误码同为 {@link ErrorCode#ACCESS_DENIED}，
 * 但 detail 文本不同，便于测试与排障）：
 * <ul>
 *   <li>未提供/未知调用方："调用方身份未知…"</li>
 *   <li>已知但缺少权限："调用方 … 缺少权限 …"</li>
 * </ul>
 * 任何拒绝都写一条 {@link AuditAction#ACCESS_DENIED} 审计。
 */
public class AuthorizationService {

    private final CallerDirectory callerDirectory;
    private final AuditService auditService;

    public AuthorizationService(CallerDirectory callerDirectory, AuditService auditService) {
        this.callerDirectory = callerDirectory;
        this.auditService = auditService;
    }

    public Caller requireCaller(String callerId) {
        return callerDirectory.find(callerId)
                .orElseThrow(() -> {
                    String safe = callerId == null ? "<缺失>" : callerId;
                    EnvelopeException ex = new EnvelopeException(ErrorCode.ACCESS_DENIED,
                            "调用方身份未知或未提供 X-Caller-Id: '" + safe + "'");
                    auditService.record(safe, AuditAction.ACCESS_DENIED, false,
                            "caller", "未知调用方被拒绝");
                    return ex;
                });
    }

    /** 校验失败抛 {@link ErrorCode#ACCESS_DENIED}，与参数错误、密钥缺失等错误码明确区分。 */
    public void requirePermission(String callerId, Permission permission) {
        Caller caller = requireCaller(callerId);
        if (!caller.permissions().contains(permission)) {
            EnvelopeException ex = new EnvelopeException(ErrorCode.ACCESS_DENIED,
                    "调用方 '" + callerId + "' 缺少权限 " + permission
                            + "（现有权限: " + caller.permissions() + "）");
            auditService.record(callerId, AuditAction.ACCESS_DENIED, false,
                    permission.name(), "权限不足被拒绝");
            throw ex;
        }
    }
}
