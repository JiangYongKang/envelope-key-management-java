package com.github.highcumontoa.envelopekeymanagementjava.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理：所有错误都归一为 {@link ApiErrorResponse}，
 * 业务错误使用错误码自带的 HTTP 状态，无法识别的异常归为 INTERNAL_ERROR。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiErrorResponse> handleApi(ApiException ex) {
        ErrorCode code = ex.getErrorCode();
        log.warn("请求失败 code={} category={} reason={}", code.name(), code.getCategory(), ex.getMessage());
        ApiErrorResponse body = new ApiErrorResponse(
                code.name(), code.getCategory().name(), code.getDefaultMessage(), ex.getMessage());
        return ResponseEntity.status(code.getHttpStatus()).body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        ErrorCode code = ErrorCode.INVALID_PARAMETER;
        ApiErrorResponse body = new ApiErrorResponse(
                code.name(), code.getCategory().name(), code.getDefaultMessage(), "请求体不是合法的 JSON");
        return ResponseEntity.status(code.getHttpStatus()).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleOther(Exception ex) {
        log.error("未预期的服务端异常", ex);
        ErrorCode code = ErrorCode.INTERNAL_ERROR;
        ApiErrorResponse body = new ApiErrorResponse(
                code.name(), code.getCategory().name(), code.getDefaultMessage(), ex.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
