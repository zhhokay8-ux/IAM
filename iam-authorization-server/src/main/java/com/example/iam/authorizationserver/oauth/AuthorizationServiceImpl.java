package com.example.iam.authorizationserver.oauth;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.oauth.AuthorizationCodePayload;
import com.example.iam.token.oauth.AuthorizationCodeService;
import com.example.iam.token.oauth.NonceService;
import com.example.iam.token.oauth.OAuthStateService;
import com.example.iam.token.oauth.PkceService;
import com.example.iam.user.service.IamUserService;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class AuthorizationServiceImpl implements AuthorizationService {

    public static final String RESPONSE_TYPE_CODE = "code";

    private final IamClientRepository clientRepository;
    private final IamPolicyEvaluator policyEvaluator;
    private final PkceService pkceService;
    private final OAuthStateService oAuthStateService;
    private final NonceService nonceService;
    private final AuthorizationCodeService authorizationCodeService;
    private final IamUserService userService;

    public AuthorizationServiceImpl(
            IamClientRepository clientRepository,
            IamPolicyEvaluator policyEvaluator,
            PkceService pkceService,
            OAuthStateService oAuthStateService,
            NonceService nonceService,
            AuthorizationCodeService authorizationCodeService,
            IamUserService userService) {
        this.clientRepository = clientRepository;
        this.policyEvaluator = policyEvaluator;
        this.pkceService = pkceService;
        this.oAuthStateService = oAuthStateService;
        this.nonceService = nonceService;
        this.authorizationCodeService = authorizationCodeService;
        this.userService = userService;
    }

    @Override
    public AuthorizationResponse authorize(AuthorizationRequest request, String subject) {
        if (request == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "authorization request is required");
        }
        requireClientExistsAndActive(request.clientId());

        if (request.responseType() == null || !RESPONSE_TYPE_CODE.equals(request.responseType().trim())) {
            throw new IamException(IamErrorCode.UNSUPPORTED_RESPONSE_TYPE, "response_type must be code");
        }

        try {
            policyEvaluator.validateRedirectUri(request.clientId(), request.redirectUri());
        } catch (IamException ex) {
            throw new IamException(IamErrorCode.INVALID_REDIRECT_URI, ex.getMessage());
        }

        try {
            return completeWithSafeRedirect(request, subject);
        } catch (IamException ex) {
            return new AuthorizationResponse(oauthErrorLocation(request.redirectUri(), request.state(), ex));
        }
    }

    private AuthorizationResponse completeWithSafeRedirect(AuthorizationRequest request, String subject) {
        List<String> scopes = parseScopes(request.scope());
        policyEvaluator.validateAuthorizationCodeScopes(request.clientId(), scopes);

        pkceService.requireS256(request.codeChallengeMethod());
        pkceService.requireValidChallenge(request.codeChallenge());
        oAuthStateService.requirePresent(request.state());
        nonceService.requirePresent(request.nonce());

        if (subject == null || subject.isBlank()) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "user session is required");
        }
        try {
            userService.requireActiveForToken(UUID.fromString(subject));
        } catch (IllegalArgumentException ex) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "user session is required");
        }

        oAuthStateService.save(request.state(), request.clientId());
        nonceService.save(request.nonce(), request.clientId() + ":" + subject);
        pkceService.saveChallenge(request.state(), request.codeChallenge().trim());

        String normalizedScope = String.join(" ", scopes);
        String code = authorizationCodeService.issue(new AuthorizationCodePayload(
                request.clientId(),
                request.redirectUri(),
                request.codeChallenge().trim(),
                PkceService.S256,
                subject,
                normalizedScope,
                request.nonce(),
                request.state()));

        URI location = UriComponentsBuilder.fromUriString(request.redirectUri())
                .queryParam("code", code)
                .queryParam("state", request.state())
                .build(true)
                .toUri();
        return new AuthorizationResponse(location);
    }

    private void requireClientExistsAndActive(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_CLIENT, "client_id is required");
        }
        var client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IamException(IamErrorCode.INVALID_CLIENT, "invalid_client"));
        if (!RegistryStatus.isActive(client.getStatus())) {
            throw new IamException(IamErrorCode.CLIENT_INACTIVE, "client is disabled: " + clientId);
        }
    }

    private static List<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        List<String> scopes = Arrays.stream(scope.trim().split("\\s+"))
                .filter(part -> !part.isBlank())
                .distinct()
                .toList();
        if (scopes.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        return scopes;
    }

    private static URI oauthErrorLocation(String redirectUri, String state, IamException ex) {
        String error = toOAuthError(ex.getErrorCode());
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri).queryParam("error", error);
        if (state != null && !state.isBlank()) {
            builder.queryParam("state", state);
        }
        return builder.build(true).toUri();
    }

    private static String toOAuthError(IamErrorCode code) {
        return switch (code) {
            case SCOPE_NOT_FOUND, SCOPE_NOT_BOUND, SCOPE_INACTIVE, PERMISSION_DENIED -> "invalid_scope";
            case USER_INACTIVE -> "access_denied";
            case UNSUPPORTED_RESPONSE_TYPE -> "unsupported_response_type";
            case INVALID_PKCE, INVALID_ARGUMENT, UNAUTHORIZED -> "invalid_request";
            default -> "invalid_request";
        };
    }
}
