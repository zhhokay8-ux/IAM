package com.example.iam.migration;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class IdentityMappingResolverImpl implements IdentityMappingResolver {

    private final IamIdentityMappingService mappingService;
    private final IamUserService userService;

    public IdentityMappingResolverImpl(IamIdentityMappingService mappingService, IamUserService userService) {
        this.mappingService = mappingService;
        this.userService = userService;
    }

    @Override
    public IdentityMappingResponse resolve(String systemCode, String externalUserId, String expectedSubjectId) {
        IdentityMappingResponse mapping = mappingService.requireMapping(systemCode, externalUserId);
        if (!UserStatus.isActive(mapping.mappingStatus())) {
            throw new IamException(IamErrorCode.MAPPING_NOT_FOUND, "identity mapping is not active");
        }
        userService.requireUser(UUID.fromString(mapping.subjectId()));
        if (StringUtils.hasText(expectedSubjectId) && !expectedSubjectId.equals(mapping.subjectId())) {
            throw new IamException(IamErrorCode.MIGRATION_USER_MISMATCH, "mapped subject does not match ticket user");
        }
        return mapping;
    }
}
