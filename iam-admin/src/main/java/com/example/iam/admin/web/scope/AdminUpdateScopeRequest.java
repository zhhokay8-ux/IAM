package com.example.iam.admin.web.scope;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminUpdateScopeRequest(@JsonProperty("scope_name") String scopeName, String description) {}
