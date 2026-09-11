package com.example.iam.common.web;

import java.time.Instant;

public record ApiErrorResponse(
        String traceId,
        String code,
        String message,
        Instant timestamp
) {
    public static ApiErrorResponse of(String traceId, String code, String message) {
        return new ApiErrorResponse(traceId, code, message, Instant.now());
    }
}
