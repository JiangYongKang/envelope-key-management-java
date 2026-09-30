package com.github.highcumontoa.envelopekeymanagementjava.error;

/**
 * 统一错误响应体：错误码 + 大类 + 消息 + 判定细节。
 */
public class ApiErrorResponse {

    private String code;
    private String category;
    private String message;
    private String detail;

    public ApiErrorResponse() {
    }

    public ApiErrorResponse(String code, String category, String message, String detail) {
        this.code = code;
        this.category = category;
        this.message = message;
        this.detail = detail;
    }

    public String getCode() {
        return code;
    }

    public String getCategory() {
        return category;
    }

    public String getMessage() {
        return message;
    }

    public String getDetail() {
        return detail;
    }
}
