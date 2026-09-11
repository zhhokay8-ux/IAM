package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Collection;
import org.springframework.util.StringUtils;

public class AudienceValidator {

    private final String resourceAudience;

    public AudienceValidator(String resourceAudience) {
        if (!StringUtils.hasText(resourceAudience)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "resource server audience is required");
        }
        this.resourceAudience = resourceAudience;
    }

    public void validate(Collection<String> audiences) {
        if (audiences == null || !audiences.contains(resourceAudience)) {
            throw new IamException(
                    IamErrorCode.INVALID_JWT_AUDIENCE, "aud does not include " + resourceAudience);
        }
    }
}
