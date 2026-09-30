package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.AccessControlService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.CallerRegistry;
import com.github.highcumontoa.envelopekeymanagementjava.auth.Permission;
import com.github.highcumontoa.envelopekeymanagementjava.error.ApiException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 鉴权与审计单测：越权必须归类为 ACCESS_DENIED(AUTHZ)，
 * 与参数错误、密钥不存在等错误区分，且每次拒绝都产生审计记录。
 */
class AccessControlTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlTest.class);

    @TempDir
    Path tempDir;

    private AccessControlService accessControl;
    private AuditService audit;

    @BeforeEach
    void setUp() throws Exception {
        audit = new AuditService(tempDir);
        var init = AuditService.class.getDeclaredMethod("initialize");
        init.setAccessible(true);
        init.invoke(audit);
        accessControl = new AccessControlService(new CallerRegistry(), audit);
    }

    @Test
    @DisplayName("权限匹配时放行")
    void allowed() {
        var caller = accessControl.check("app-crypto", Permission.DECRYPT);
        assertEquals("app-crypto", caller.id());
        log.info("[判定依据] caller=app-crypto 权限=DECRYPT 放行，权限集合={}", caller.permissions());
    }

    @Test
    @DisplayName("已注册但缺少权限 -> ACCESS_DENIED(AUTHZ)")
    void missingPermission() {
        ApiException ex = assertThrows(ApiException.class,
                () -> accessControl.check("app-encrypt-only", Permission.DECRYPT));
        assertEquals(ErrorCode.ACCESS_DENIED, ex.getErrorCode());
        assertEquals(ErrorCode.Category.AUTHZ, ex.getErrorCode().getCategory());
        log.info("[关键输入] caller=app-encrypt-only, 要求 DECRYPT -> code={}, http={}, message={}",
                ex.getErrorCode(), ex.getErrorCode().getHttpStatus(), ex.getMessage());

        var deniedRecords = audit.query("app-encrypt-only", AuditAction.ACCESS_DENIED);
        assertEquals(1, deniedRecords.size());
        assertEquals(AuditEvent.RESULT_DENIED, deniedRecords.get(0).result());
        assertTrue(deniedRecords.get(0).detail().contains("DECRYPT"));
        log.info("[判定依据] 审计已记录 #{} detail={}", deniedRecords.get(0).id(), deniedRecords.get(0).detail());
    }

    @Test
    @DisplayName("未知调用方 -> ACCESS_DENIED(AUTHZ)，且与参数错误的类别不同")
    void unknownCaller() {
        ApiException unknown = assertThrows(ApiException.class,
                () -> accessControl.check("nobody", Permission.ENCRYPT));
        ApiException blank = assertThrows(ApiException.class,
                () -> accessControl.check("  ", Permission.ENCRYPT));
        log.info("[关键输入] 未知调用方 -> {}；空白身份 -> {}",
                unknown.getErrorCode(), blank.getErrorCode());
        assertEquals(ErrorCode.ACCESS_DENIED, unknown.getErrorCode());
        assertEquals(ErrorCode.ACCESS_DENIED, blank.getErrorCode());
        assertEquals(2, audit.query(null, AuditAction.ACCESS_DENIED).size());
    }

    @Test
    @DisplayName("错误可区分：AUTHZ(403) vs PARAM(400) vs KEY(404)")
    void errorCategoriesAreDistinguishable() {
        ApiException authz = assertThrows(ApiException.class,
                () -> accessControl.check("auditor", Permission.ROTATE));
        ApiException param = ApiException.of(ErrorCode.INVALID_PARAMETER, "plaintext 为空");
        ApiException keyMissing = ApiException.of(ErrorCode.KEY_VERSION_NOT_FOUND, "主密钥版本 99");

        log.info("[判定依据] 越权: code={}, category={}, http={}", authz.getErrorCode(),
                authz.getErrorCode().getCategory(), authz.getErrorCode().getHttpStatus());
        log.info("[判定依据] 参数: code={}, category={}, http={}", param.getErrorCode(),
                param.getErrorCode().getCategory(), param.getErrorCode().getHttpStatus());
        log.info("[判定依据] 密钥: code={}, category={}, http={}", keyMissing.getErrorCode(),
                keyMissing.getErrorCode().getCategory(), keyMissing.getErrorCode().getHttpStatus());

        assertEquals(403, authz.getErrorCode().getHttpStatus());
        assertEquals(400, param.getErrorCode().getHttpStatus());
        assertEquals(404, keyMissing.getErrorCode().getHttpStatus());
        assertEquals(ErrorCode.Category.AUTHZ, authz.getErrorCode().getCategory());
        assertEquals(ErrorCode.Category.PARAM, param.getErrorCode().getCategory());
        assertEquals(ErrorCode.Category.KEY, keyMissing.getErrorCode().getCategory());
    }
}
