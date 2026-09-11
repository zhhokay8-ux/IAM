package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.domain.ClientType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class ClientAuthenticationProvider {

    private static final String BASIC_PREFIX = "Basic ";

    private final IamClientRepository clientRepository;

    public ClientAuthenticationProvider(IamClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    public IamClientEntity authenticate(HttpServletRequest httpRequest, TokenRequest request) {
        BasicCredentials basic = parseBasic(httpRequest == null ? null : httpRequest.getHeader("Authorization"));
        String clientId = firstNonBlank(basic == null ? null : basic.clientId(), request == null ? null : request.clientId());
        String secret = firstNonBlank(basic == null ? null : basic.secret(), request == null ? null : request.clientSecret());
        if (basic != null
                && request != null
                && request.clientId() != null
                && !request.clientId().isBlank()
                && !basic.clientId().equals(request.clientId())) {
            throw invalidClient();
        }
        return authenticate(clientId, secret);
    }

    public IamClientEntity authenticate(String clientId, String secret) {
        if (clientId == null || clientId.isBlank()) {
            throw invalidClient();
        }
        IamClientEntity client = clientRepository.findByClientId(clientId).orElseThrow(this::invalidClient);
        if (!RegistryStatus.isActive(client.getStatus())) {
            throw new IamException(IamErrorCode.CLIENT_INACTIVE, "client is disabled: " + clientId);
        }
        if (ClientType.PUBLIC.equalsIgnoreCase(client.getClientType())
                || "none".equalsIgnoreCase(client.getTokenEndpointAuthMethod())) {
            return client;
        }
        if (secret == null || client.getClientSecretHash() == null) {
            throw invalidClient();
        }
        String stored = client.getClientSecretHash();
        boolean hashed = HashUtils.constantTimeEquals(stored, HashUtils.sha256Hex(secret));
        boolean plaintext = HashUtils.constantTimeEquals(stored, secret);
        if (!hashed && !plaintext) {
            throw invalidClient();
        }
        return client;
    }

    public IamClientEntity authenticateConfidential(String clientId, String secret) {
        IamClientEntity client = authenticate(clientId, secret);
        requireConfidential(client);
        return client;
    }

    public static void requireConfidential(IamClientEntity client) {
        if (client == null || !ClientType.CONFIDENTIAL.equalsIgnoreCase(client.getClientType())) {
            throw new IamException(
                    IamErrorCode.CLIENT_CREDENTIALS_NOT_ALLOWED, "client_credentials requires a confidential client");
        }
    }

    private BasicCredentials parseBasic(String header) {
        if (header == null || !header.toLowerCase(Locale.ROOT).startsWith("basic ")) {
            return null;
        }
        try {
            String decoded = new String(
                    Base64.getDecoder().decode(header.substring(BASIC_PREFIX.length()).trim()),
                    StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                return new BasicCredentials(decoded, "");
            }
            return new BasicCredentials(decoded.substring(0, colon), decoded.substring(colon + 1));
        } catch (IllegalArgumentException ex) {
            throw invalidClient();
        }
    }

    private IamException invalidClient() {
        return new IamException(IamErrorCode.INVALID_CLIENT, "invalid_client");
    }

    private static String firstNonBlank(String primary, String fallback) {
        if (primary != null && !primary.isBlank()) {
            return primary;
        }
        return fallback;
    }

    private record BasicCredentials(String clientId, String secret) {
    }
}
