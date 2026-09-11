package com.example.iam.migration;

import com.example.iam.user.dto.IdentityMappingResponse;

public interface IdentityMappingResolver {

    IdentityMappingResponse resolve(String systemCode, String externalUserId, String expectedSubjectId);
}
