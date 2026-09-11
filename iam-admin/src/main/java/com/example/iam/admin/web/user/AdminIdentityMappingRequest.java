package com.example.iam.admin.web.user;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminIdentityMappingRequest(
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("system_code") String systemCode,
        @JsonProperty("external_user_id") String externalUserId,
        @JsonProperty("external_username") String externalUsername,
        @JsonProperty("mapping_status") String mappingStatus) {}
