package com.example.iam.embed;

import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.stereotype.Component;

@Component
public class OriginValidator {

    private final IamOriginValidator originValidator;

    public OriginValidator(IamOriginValidator originValidator) {
        this.originValidator = originValidator;
    }

    public void requireExplicitOrigin(String origin) {
        if (origin != null && origin.contains("*")) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "wildcard origin is not allowed");
        }
        originValidator.validateSyntax(origin);
    }

    public void requireMatch(String requested, String bound) {
        requireExplicitOrigin(requested);
        if (bound == null || !bound.equals(requested)) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin does not match the embed binding");
        }
    }
}
