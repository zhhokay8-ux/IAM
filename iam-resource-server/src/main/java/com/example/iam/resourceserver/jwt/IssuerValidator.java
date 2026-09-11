package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.util.StringUtils;

public class IssuerValidator {

    private final String expectedIssuer;

    public IssuerValidator(String expectedIssuer) {
        if (!StringUtils.hasText(expectedIssuer)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "resource server issuer is required");
        }
        this.expectedIssuer = expectedIssuer;
    }

    public void validate(String issuer) {
        if (!expectedIssuer.equals(issuer)) {
            throw new IamException(IamErrorCode.INVALID_JWT_ISSUER, "iss does not match the resource server issuer");
        }
    }
}
