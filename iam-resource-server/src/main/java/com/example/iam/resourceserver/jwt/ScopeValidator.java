package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Collection;

public class ScopeValidator {

    public void validate(Collection<String> tokenScopes, String requiredScope) {
        if (requiredScope == null || requiredScope.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "required scope is missing");
        }
        if (tokenScopes == null || !tokenScopes.contains(requiredScope)) {
            throw new IamException(IamErrorCode.INSUFFICIENT_SCOPE, "missing required scope: " + requiredScope);
        }
    }
}
