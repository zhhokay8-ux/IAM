package com.example.iam.common.security;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SensitiveDataMasker {

    private static final String MASK = "***";
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(access_token|refresh_token|id_token|client_secret|authorization_code|logout_token|code_verifier|(?<!\\w)code)([\"'\\s:=]+)([^\\s\"'&,}]+)");
    private static final Pattern BEARER = Pattern.compile("(?i)(Bearer\\s+)([A-Za-z0-9\\-._~+/]+=*)");

    private SensitiveDataMasker() {
    }

    public static String mask(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String masked = BEARER.matcher(value).replaceAll("$1" + MASK);
        Matcher matcher = SENSITIVE.matcher(masked);
        StringBuffer buffer = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(buffer, Matcher.quoteReplacement(matcher.group(1) + matcher.group(2) + MASK));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }
}
