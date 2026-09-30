package com.github.highcumontoa.envelopekeymanagementjava.error;

/** 统一业务异常，携带可区分的错误码。 */
public class EnvelopeException extends RuntimeException {

    private final ErrorCode code;

    public EnvelopeException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public EnvelopeException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode getCode() {
        return code;
    }
}
