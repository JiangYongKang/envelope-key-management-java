package com.github.highcumontoa.envelopekeymanagementjava.error;

/**
 * 业务错误码。
 *
 * <p>错误按原因分类，调用方可依据 {@code name()} 与 {@link #getCategory()} 做可区分的处理：</p>
 * <ul>
 *     <li>{@code PARAM}：请求参数本身非法（空值、编码错误、结构头不合法）；</li>
 *     <li>{@code CIPHERTEXT}：密文格式类问题（截断、Base64/结构不合法）；</li>
 *     <li>{@code INTEGRITY}：密文通过了格式校验，但认证失败（被篡改或引用了错误的密钥）；</li>
 *     <li>{@code KEY}：引用的密钥版本不存在；</li>
 *     <li>{@code AUTHZ}：调用方不存在或缺少所需权限；</li>
 *     <li>{@code INTERNAL}：服务端内部错误。</li>
 * </ul>
 */
public enum ErrorCode {

    /** 参数缺失或不合法（类别 PARAM，400）。 */
    INVALID_PARAMETER(Category.PARAM, 400, "请求参数缺失或不合法"),

    /** 密文 Base64 编码或整体结构非法（类别 CIPHERTEXT，400）。 */
    MALFORMED_CIPHERTEXT(Category.CIPHERTEXT, 400, "密文格式非法"),

    /** 密文结构存在但被截断，长度字段与实际载荷不符（类别 CIPHERTEXT，400）。 */
    CIPHERTEXT_TRUNCATED(Category.CIPHERTEXT, 400, "密文被截断"),

    /** 密文认证失败：内容被篡改、IV/标签被改动或密钥不匹配（类别 INTEGRITY，400）。 */
    CIPHERTEXT_TAMPERED(Category.INTEGRITY, 400, "密文完整性校验失败（疑似被篡改）"),

    /** 密文引用的主密钥版本不存在（类别 KEY，404）。 */
    KEY_VERSION_NOT_FOUND(Category.KEY, 404, "密文引用的密钥版本不存在"),

    /** 调用方身份未知或没有执行该操作的权限（类别 AUTHZ，403）。 */
    ACCESS_DENIED(Category.AUTHZ, 403, "越权访问：调用方不存在或权限不足"),

    /** 服务端内部错误（类别 INTERNAL，500）。 */
    INTERNAL_ERROR(Category.INTERNAL, 500, "服务内部错误");

    /** 错误大类，用于与具体错误码正交的粗粒度分类。 */
    public enum Category {
        PARAM, CIPHERTEXT, INTEGRITY, KEY, AUTHZ, INTERNAL
    }

    private final Category category;
    private final int httpStatus;
    private final String defaultMessage;

    ErrorCode(Category category, int httpStatus, String defaultMessage) {
        this.category = category;
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public Category getCategory() {
        return category;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
