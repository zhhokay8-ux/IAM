package com.example.iam.admin.web.client;

import java.util.List;

public record AdminPageResponse<T>(List<T> content, int page, int size, long totalElements) {}
