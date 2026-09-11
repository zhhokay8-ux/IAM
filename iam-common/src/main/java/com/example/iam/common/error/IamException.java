package com.example.iam.common.error;

import java.util.Objects;

public class IamException extends RuntimeException {

    private final IamErrorCode errorCode;

    public IamException(IamErrorCode errorCode) {
        this(errorCode, errorCode.getMessage(), null);
    }

    public IamException(IamErrorCode errorCode, String message) {
        this(errorCode, message, null);
    }

    public IamException(IamErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
    }

    public IamErrorCode getErrorCode() {
        return errorCode;
    }
}
