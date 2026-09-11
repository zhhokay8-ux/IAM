package com.example.iam.migration;

import java.util.List;

public record CurrentUser(String subjectId, String username, String tenantId, List<String> roles) {

    public CurrentUser {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }
}
