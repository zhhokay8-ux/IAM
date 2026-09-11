package com.example.iam.user.context;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.entity.IamUserEntity;
import org.springframework.stereotype.Component;

@Component
public class UserContextFactory {

    public UserContext from(IamUserEntity user) {
        if (user == null || user.getSubjectId() == null) {
            throw new IamException(IamErrorCode.USER_NOT_FOUND, "user is required");
        }
        return new UserContext(
                user.getSubjectId().toString(),
                user.getUsername(),
                user.getDisplayName(),
                user.getEmail(),
                user.getTenantId(),
                user.getOrgId(),
                user.getStatus());
    }

    public UserContext forToken(IamUserEntity user) {
        UserContext context = from(user);
        if (!UserStatus.isActive(user.getStatus())) {
            throw new IamException(IamErrorCode.USER_INACTIVE, "inactive user cannot obtain a token");
        }
        if (context.username() != null && context.username().equals(context.subjectId())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "JWT sub must not be username");
        }
        if (context.email() != null && context.email().equals(context.subjectId())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "JWT sub must not be email");
        }
        return context;
    }
}
