package com.github.highcumontoa.envelopekeymanagementjava.web;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.AccessControlService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Permission;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.key.MasterKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 信封加密 / 密钥轮换 / 审计查询的 HTTP 接口。
 *
 * <p>统一处理顺序：鉴权（失败由鉴权服务记 ACCESS_DENIED）→ 参数校验 → 执行业务，
 * 业务成功记 SUCCESS，业务失败记 REQUEST_REJECTED(FAILURE)，保证每次请求都可追溯。</p>
 */
@RestController
@RequestMapping("/api/v1")
public class EnvelopeController {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeController.class);

    private final EnvelopeCryptoService cryptoService;
    private final KeyManagementService keyManagementService;
    private final AccessControlService accessControl;
    private final AuditService auditService;

    public EnvelopeController(EnvelopeCryptoService cryptoService,
                              KeyManagementService keyManagementService,
                              AccessControlService accessControl,
                              AuditService auditService) {
        this.cryptoService = cryptoService;
        this.keyManagementService = keyManagementService;
        this.accessControl = accessControl;
        this.auditService = auditService;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody EncryptRequest request) {
        String callerId = request.getCallerId();
        accessControl.check(callerId, Permission.ENCRYPT);
        requireText(request.getPlaintext(), "plaintext");
        try {
            EnvelopeCryptoService.Encrypted result = cryptoService.encrypt(request.getPlaintext());
            auditService.record(callerId, AuditAction.ENCRYPT, AuditEvent.RESULT_SUCCESS,
                    "kekVersion=" + result.masterKeyVersion() + "，dekId=" + result.dataKeyId()
                            + "，明文长度=" + request.getPlaintext().length());
            return new EncryptResponse(result.ciphertext(), result.masterKeyVersion(), result.dataKeyId());
        } catch (ApiException e) {
            auditService.record(callerId, AuditAction.REQUEST_REJECTED, AuditEvent.RESULT_FAILURE,
                    "ENCRYPT 失败：" + e.getErrorCode().name() + "：" + e.getMessage());
            throw e;
        }
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) {
        String callerId = request.getCallerId();
        accessControl.check(callerId, Permission.DECRYPT);
        requireText(request.getCiphertext(), "ciphertext");
        try {
            String plaintext = cryptoService.decrypt(request.getCiphertext());
            auditService.record(callerId, AuditAction.DECRYPT, AuditEvent.RESULT_SUCCESS,
                    "密文长度=" + request.getCiphertext().length() + "，明文长度=" + plaintext.length());
            return new DecryptResponse(plaintext);
        } catch (ApiException e) {
            auditService.record(callerId, AuditAction.REQUEST_REJECTED, AuditEvent.RESULT_FAILURE,
                    "DECRYPT 失败：" + e.getErrorCode().name() + "：" + e.getMessage());
            throw e;
        }
    }

    @PostMapping("/keys/rotate")
    public RotateResponse rotate(@RequestBody RotateRequest request) {
        String callerId = request.getCallerId();
        accessControl.check(callerId, Permission.ROTATE);
        try {
            MasterKey newKey = keyManagementService.rotateMasterKey();
            auditService.record(callerId, AuditAction.ROTATE, AuditEvent.RESULT_SUCCESS,
                    "新主密钥版本=" + newKey.getVersion());
            return new RotateResponse(newKey.getVersion(), newKey.getCreatedAt());
        } catch (RuntimeException e) {
            auditService.record(callerId, AuditAction.REQUEST_REJECTED, AuditEvent.RESULT_FAILURE,
                    "ROTATE 失败：" + e.getMessage());
            throw e;
        }
    }

    /** 查询当前主密钥版本，便于本地验证轮换结果（需 AUDIT_READ 权限）。 */
    @GetMapping("/keys/current")
    public RotateResponse currentKey(@RequestParam String callerId) {
        accessControl.check(callerId, Permission.AUDIT_READ);
        MasterKey current = keyManagementService.currentMasterKey();
        return new RotateResponse(current.getVersion(), current.getCreatedAt());
    }

    /** 查询审计记录，可按调用方与操作类型过滤。 */
    @GetMapping("/audit")
    public List<AuditEventView> audit(@RequestParam String callerId,
                                      @RequestParam(required = false) String action) {
        accessControl.check(callerId, Permission.AUDIT_READ);
        AuditAction actionFilter = null;
        if (action != null && !action.isBlank()) {
            try {
                actionFilter = AuditAction.valueOf(action);
            } catch (IllegalArgumentException e) {
                throw ApiException.of(com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode.INVALID_PARAMETER,
                        "未知的审计操作类型 " + action);
            }
        }
        return auditService.query(null, actionFilter).stream().map(AuditEventView::from).toList();
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw ApiException.of(com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode.INVALID_PARAMETER,
                    field + " 不能为空");
        }
    }
}
