package com.example.iam.clientregistry.validation;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.net.URI;
import java.util.Collection;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class IamRedirectUriValidator {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");

    public void validateRedirectUri(String requested, Collection<String> registeredUris) {
        validateSyntax(requested);
        if (registeredUris == null || registeredUris.stream().noneMatch(requested::equals)) {
            throw new IamException(IamErrorCode.REDIRECT_URI_MISMATCH, "redirect_uri does not match a registered value");
        }
    }

    public void validateSyntax(String redirectUri) {
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri is required");
        }
        if (redirectUri.chars().anyMatch(ch -> ch <= 32)) {
            throw new IamException(
                    IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri must not contain whitespace or control characters");
        }
        if (containsWildcard(redirectUri)) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "wildcard redirect URI is not allowed");
        }
        URI uri;
        try {
            uri = URI.create(redirectUri);
        } catch (IllegalArgumentException ex) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri is not a valid URI");
        }
        if (uri.getScheme() == null || uri.getHost() == null || !uri.isAbsolute()) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri must be an absolute URI");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri scheme is not allowed");
        }
        if ("http".equals(scheme) && !isHttpHostAllowed(uri.getHost())) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "http redirect_uri is only allowed for loopback");
        }
        if (uri.getRawUserInfo() != null || redirectUri.contains("@")) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri must not contain userinfo");
        }
        if (uri.getFragment() != null) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, "redirect_uri must not contain a fragment");
        }
    }

    private static boolean containsWildcard(String redirectUri) {
        return redirectUri.contains("*") || redirectUri.contains("{") || redirectUri.contains("}");
    }

    private static boolean isLoopback(String host) {
        String value = host.toLowerCase(Locale.ROOT);
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        return "localhost".equals(value) || "127.0.0.1".equals(value) || "::1".equals(value);
    }

    /**
     * http 仅允许本机回环，以及内网字面量 IP（RFC1918 / 链路本地），避免公网 http 回调。
     * 不解析主机名，避免 DNS 旁路。
     */
    private static boolean isHttpHostAllowed(String host) {
        if (isLoopback(host)) {
            return true;
        }
        return isPrivateIpv4Literal(host);
    }

    private static boolean isPrivateIpv4Literal(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int[] oct = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                oct[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException ex) {
                return false;
            }
            if (oct[i] < 0 || oct[i] > 255) {
                return false;
            }
        }
        if (oct[0] == 10) {
            return true;
        }
        if (oct[0] == 192 && oct[1] == 168) {
            return true;
        }
        if (oct[0] == 172 && oct[1] >= 16 && oct[1] <= 31) {
            return true;
        }
        return oct[0] == 169 && oct[1] == 254;
    }
}
