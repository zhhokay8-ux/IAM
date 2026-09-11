package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Collection;

public class RoleValidator {

    public void validate(Collection<String> tokenRoles, String requiredRole) {
        if (requiredRole == null || requiredRole.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "required role is missing");
        }
        if (tokenRoles == null || !tokenRoles.contains(requiredRole)) {
            throw new IamException(IamErrorCode.INSUFFICIENT_ROLE, "missing required role: " + requiredRole);
        }
    }
}
