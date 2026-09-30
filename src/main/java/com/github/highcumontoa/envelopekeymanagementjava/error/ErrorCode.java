package com.github.highcumontoa.envelopekeymanagementjava.error;

/** 业务错误分类，每一类都对应可区分的错误码。 */
public enum ErrorCode {
    INVALID_PARAMETER("请求参数缺失或非法"),
    CIPHERTEXT_MALFORMED("密文格式非法或被截断"),
    CIPHERTEXT_TAMPERED("密文完整性校验失败，内容可能被篡改"),
    KEY_VERSION_NOT_FOUND("密文引用的主密钥版本不存在"),
    DATA_KEY_NOT_FOUND("密文引用的数据密钥不存在"),
    ACCESS_DENIED("调用方无权限或身份未知");

    private final String defaultMessage;

    ErrorCode(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
