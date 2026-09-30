package com.github.highcumontoa.envelopekeymanagementjava.error;

/**
 * 可分类的业务异常。每个异常携带稳定的 {@link ErrorCode}，
 * 由全局异常处理器转换为统一错误响应，保证错误原因可区分、可复现。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ApiException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public static ApiException of(ErrorCode errorCode, String detail) {
        return new ApiException(errorCode, errorCode.getDefaultMessage() + "：" + detail);
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
