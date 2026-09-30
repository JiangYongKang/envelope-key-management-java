package com.github.highcumontoa.envelopekeymanagementjava.web;

import com.github.highcumontoa.envelopekeymanagementjava.error.EnvelopeException;
import com.github.highcumontoa.envelopekeymanagementjava.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一异常 -> HTTP 响应。
 * 错误码与 HTTP 状态一一对应，调用方仅凭响应即可区分错误类别。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** 错误码到 HTTP 状态的固定映射。 */
    private HttpStatus statusOf(ErrorCode code) {
        return switch (code) {
            case INVALID_PARAMETER, CIPHERTEXT_MALFORMED -> HttpStatus.BAD_REQUEST;
            case CIPHERTEXT_TAMPERED -> HttpStatus.UNPROCESSABLE_ENTITY;
            case KEY_VERSION_NOT_FOUND, DATA_KEY_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case ACCESS_DENIED -> HttpStatus.FORBIDDEN;
        };
    }

    @ExceptionHandler(EnvelopeException.class)
    public ResponseEntity<Map<String, Object>> handleBusiness(EnvelopeException ex) {
        HttpStatus status = statusOf(ex.getCode());
        log.warn("业务拒绝 | code={} | httpStatus={} | reason={}",
                ex.getCode(), status.value(), ex.getMessage());
        return ResponseEntity.status(status).body(body(ex.getCode().name(), ex.getMessage()));
    }

    /** 请求体缺失/JSON 无法解析统一归类为参数错误。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException ex) {
        log.warn("请求体不可读: {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(body(ErrorCode.INVALID_PARAMETER.name(), "请求体缺失或不是合法 JSON"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        log.error("未预期的服务端异常", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body("INTERNAL_ERROR", "服务内部错误: " + ex.getMessage()));
    }

    private Map<String, Object> body(String code, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timestamp", Instant.now().toString());
        m.put("errorCode", code);
        m.put("message", message);
        return m;
    }
}
