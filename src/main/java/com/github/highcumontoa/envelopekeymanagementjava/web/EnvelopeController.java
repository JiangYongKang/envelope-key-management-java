package com.github.highcumontoa.envelopekeymanagementjava.web;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Permission;
import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyVersion;
import com.github.highcumontoa.envelopekeymanagementjava.service.AuthorizationService;
import com.github.highcumontoa.envelopekeymanagementjava.service.EnvelopeEncryptionService;
import com.github.highcumontoa.envelopekeymanagementjava.service.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.web.dto.AuditEventView;
import com.github.highcumontoa.envelopekeymanagementjava.web.dto.DecryptRequest;
import com.github.highcumontoa.envelopekeymanagementjava.web.dto.EncryptRequest;
import com.github.highcumontoa.envelopekeymanagementjava.web.dto.KeyStatusResponse;
import com.github.highcumontoa.envelopekeymanagementjava.web.dto.RotateResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * REST 入口。调用方通过 {@code X-Caller-Id} 请求头标识（本地模拟身份）。
 * 每个写操作先做权限校验，再执行业务。
 */
@RestController
@RequestMapping("/api/keys")
public class EnvelopeController {

    private static final String CALLER_HEADER = "X-Caller-Id";

    private final EnvelopeEncryptionService encryptionService;
    private final KeyManagementService keyManagementService;
    private final AuthorizationService authorizationService;
    private final AuditService auditService;

    public EnvelopeController(EnvelopeEncryptionService encryptionService,
                              KeyManagementService keyManagementService,
                              AuthorizationService authorizationService,
                              AuditService auditService) {
        this.encryptionService = encryptionService;
        this.keyManagementService = keyManagementService;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
    }

    /** 加密：需要 ENCRYPT 权限。 */
    @PostMapping("/encrypt")
    public Map<String, String> encrypt(@RequestHeader(value = CALLER_HEADER, required = false) String callerId,
                                       @RequestBody(required = false) EncryptRequest request) {
        authorizationService.requirePermission(callerId, Permission.ENCRYPT);
        if (request == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "请求体缺失");
        }
        String ciphertext = encryptionService.encrypt(callerId, request.plaintext());
        return Map.of("ciphertext", ciphertext);
    }

    /** 解密：需要 DECRYPT 权限。 */
    @PostMapping("/decrypt")
    public Map<String, String> decrypt(@RequestHeader(value = CALLER_HEADER, required = false) String callerId,
                                       @RequestBody(required = false) DecryptRequest request) {
        authorizationService.requirePermission(callerId, Permission.DECRYPT);
        if (request == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "请求体缺失");
        }
        String plaintext = encryptionService.decrypt(callerId, request.ciphertext());
        return Map.of("plaintext", plaintext);
    }

    /** 轮换主密钥：需要 ROTATE 权限。 */
    @PostMapping("/rotate")
    public RotateResponse rotate(@RequestHeader(value = CALLER_HEADER, required = false) String callerId) {
        authorizationService.requirePermission(callerId, Permission.ROTATE);
        KeyManagementService.RotationResult rotated = keyManagementService.rotateMasterKey();
        KeyVersion version = rotated.version();
        return new RotateResponse(version.version(), version.createdAt(), rotated.coalesced());
    }

    /** 查询主密钥版本状态：任何已知调用方均可（至少要能识别身份）。 */
    @GetMapping("/status")
    public KeyStatusResponse status(@RequestHeader(value = CALLER_HEADER, required = false) String callerId) {
        authorizationService.requireCaller(callerId);
        List<Integer> versions = keyManagementService.listMasterVersions().stream()
                .map(KeyVersion::version)
                .sorted()
                .toList();
        int current = versions.isEmpty() ? 0 : versions.get(versions.size() - 1);
        return new KeyStatusResponse(current, versions);
    }

    /** 查询审计记录：需要 AUDIT_READ 权限。 */
    @GetMapping("/audit")
    public List<AuditEventView> audit(@RequestHeader(value = CALLER_HEADER, required = false) String callerId,
                                      @RequestParam(value = "caller", required = false) String filterCaller,
                                      @RequestParam(value = "action", required = false) String filterAction) {
        authorizationService.requirePermission(callerId, Permission.AUDIT_READ);
        AuditAction action = null;
        if (filterAction != null && !filterAction.isBlank()) {
            try {
                action = AuditAction.valueOf(filterAction);
            } catch (IllegalArgumentException e) {
                throw new EnvelopeException(ErrorCode.INVALID_PARAMETER,
                        "未知的审计操作类型: " + filterAction);
            }
        }
        auditService.record(callerId, AuditAction.AUDIT_QUERY, true, "audit",
                "查询审计记录，过滤条件 caller=" + filterCaller + ", action=" + action);
        return auditService.query(filterCaller, action).stream()
                .map(EnvelopeController::toView)
                .toList();
    }

    private static AuditEventView toView(AuditEvent e) {
        return new AuditEventView(e.eventId(), e.timestamp(), e.callerId(),
                e.action().name(), e.success(), e.target(), e.detail());
    }
}
