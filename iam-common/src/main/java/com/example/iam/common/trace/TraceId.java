package com.example.iam.common.trace;

import java.util.UUID;
import org.slf4j.MDC;

public final class TraceId {

    public static final String MDC_KEY = "traceId";

    private TraceId() {
    }

    public static String newValue() {
        return UUID.randomUUID().toString();
    }

    public static String current() {
        return MDC.get(MDC_KEY);
    }

    public static String currentOrNew() {
        String existing = current();
        if (existing != null && !existing.isBlank()) {
            return existing;
        }
        String generated = newValue();
        put(generated);
        return generated;
    }

    public static void put(String traceId) {
        if (traceId == null || traceId.isBlank()) {
            MDC.remove(MDC_KEY);
            return;
        }
        MDC.put(MDC_KEY, traceId);
    }

    public static void clear() {
        MDC.remove(MDC_KEY);
    }
}
