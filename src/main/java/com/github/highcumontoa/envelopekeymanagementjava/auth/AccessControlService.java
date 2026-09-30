package com.github.highcumontoa.envelopekeymanagementjava.auth;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 调用方鉴权：身份未知或缺少权限都归类为 {@link ErrorCode#ACCESS_DENIED}，
 * 与参数错误（PARAM）、密钥不存在（KEY）明确区分；每次拒绝都写审计。
 */
@Component
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final CallerRegistry callerRegistry;
    private final AuditService auditService;

    public AccessControlService(CallerRegistry callerRegistry, AuditService auditService) {
        this.callerRegistry = callerRegistry;
        this.auditService = auditService;
    }

    /**
     * 校验调用方是否拥有指定权限，不通过则记录 ACCESS_DENIED 审计并抛出 ACCESS_DENIED 异常。
     */
    public Caller check(String callerId, Permission permission) {
        if (callerId == null || callerId.isBlank()) {
            return deny(callerId, permission, "调用方身份缺失");
        }
        Caller caller = callerRegistry.find(callerId);
        if (caller == null) {
            return deny(callerId, permission, "调用方未注册");
        }
        if (!caller.has(permission)) {
            return deny(callerId, permission,
                    "调用方权限集合 " + caller.permissions() + " 不包含 " + permission);
        }
        log.debug("鉴权通过 caller={} permission={}", callerId, permission);
        return caller;
    }

    private Caller deny(String callerId, Permission permission, String reason) {
        String detail = "permission=" + permission + "，判定依据：" + reason;
        log.warn("越权拒绝 caller={} {}", callerId, detail);
        AuditEvent event = auditService.record(
                callerId, AuditAction.ACCESS_DENIED, AuditEvent.RESULT_DENIED, detail);
        throw new ApiException(ErrorCode.ACCESS_DENIED,
                ErrorCode.ACCESS_DENIED.getDefaultMessage() + "（审计记录 #" + event.id() + "）：" + detail);
    }
}
