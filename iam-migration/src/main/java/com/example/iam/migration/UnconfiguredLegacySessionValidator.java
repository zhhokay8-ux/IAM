package com.example.iam.migration;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.stereotype.Component;

@Component
public class UnconfiguredLegacySessionValidator implements LegacySessionValidator {

    @Override
    public LegacyPrincipal requireValid(String legacySessionCookie) {
        throw new IamException(
                IamErrorCode.UNAUTHORIZED, "legacy session validator is not configured on this node");
    }
}
