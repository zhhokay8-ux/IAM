package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.oauth.AuthorizationCodePayload;
import com.example.iam.token.oauth.AuthorizationCodeService;
import com.example.iam.token.oauth.IdTokenClaims;
import com.example.iam.token.oauth.IdTokenService;
import com.example.iam.token.oauth.PkceService;
import com.example.iam.token.oauth.RefreshTokenService;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.service.IamUserService;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationCodeTokenGrantHandler implements TokenGrantHandler {

    private final AuthorizationCodeService authorizationCodeService;
    private final PkceService pkceService;
    private final IamUserService userService;
    private final IamPolicyEvaluator policyEvaluator;
    private final AccessTokenService accessTokenService;
    private final IdTokenService idTokenService;
    private final RefreshTokenService refreshTokenService;

    public AuthorizationCodeTokenGrantHandler(
            AuthorizationCodeService authorizationCodeService,
            PkceService pkceService,
            IamUserService userService,
            IamPolicyEvaluator policyEvaluator,
            AccessTokenService accessTokenService,
            IdTokenService idTokenService,
            RefreshTokenService refreshTokenService) {
        this.authorizationCodeService = authorizationCodeService;
        this.pkceService = pkceService;
        this.userService = userService;
        this.policyEvaluator = policyEvaluator;
        this.accessTokenService = accessTokenService;
        this.idTokenService = idTokenService;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public boolean supports(String grantType) {
        return "authorization_code".equals(grantType);
    }

    @Override
    public TokenResponse handle(TokenRequest request, IamClientEntity client) {
        if (request.redirectUri() == null || request.redirectUri().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "redirect_uri is required");
        }
        AuthorizationCodePayload payload = authorizationCodeService
                .find(request.code())
                .orElseThrow(() -> new IamException(
                        IamErrorCode.INVALID_GRANT, "authorization code is invalid, expired, or already used"));
        if (!client.getClientId().equals(payload.clientId()) || !request.redirectUri().equals(payload.redirectUri())) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "authorization code does not match client or redirect_uri");
        }
        pkceService.requireValidChallenge(request.codeVerifier());
        if (!pkceService.matches(request.codeVerifier(), payload.codeChallenge())) {
            throw new IamException(IamErrorCode.INVALID_PKCE, "code_verifier does not match code_challenge");
        }
        authorizationCodeService.consume(request.code(), client.getClientId(), request.redirectUri());

        List<String> grantedScopes = split(payload.scope());
        List<String> requestedScopes = request.scope() == null || request.scope().isBlank()
                ? grantedScopes
                : split(request.scope());
        if (!grantedScopes.containsAll(requestedScopes)) {
            throw new IamException(IamErrorCode.PERMISSION_DENIED, "requested scope exceeds the authorization grant");
        }
        List<String> audiences = policyEvaluator.resolveAudiences(
                client.getClientId(), requestedScopes, GrantType.AUTHORIZATION_CODE);
        if (request.audience() != null && !request.audience().isBlank()) {
            if (!audiences.contains(request.audience())) {
                throw new IamException(IamErrorCode.PERMISSION_DENIED, "requested audience is not allowed");
            }
            audiences = List.of(request.audience());
        }

        UUID subjectId = UUID.fromString(payload.subject());
        UserContext user = userService.requireActiveForToken(subjectId);
        IamUserEntity userEntity = userService.requireUser(subjectId);
        Instant now = Instant.now();
        Duration ttl = accessTtl(client);
        Instant exp = now.plus(ttl);
        String scope = String.join(" ", requestedScopes);
        String accessToken = accessTokenService.issue(new AccessTokenClaims(
                user.subjectId(),
                audiences,
                client.getClientId(),
                scope,
                List.of(),
                user.tenantId(),
                user.orgId(),
                now,
                exp,
                null,
                null,
                null));
        String idToken = requestedScopes.contains("openid")
                ? idTokenService.issue(new IdTokenClaims(
                        user.subjectId(), client.getClientId(), now, exp, payload.nonce()))
                : null;
        RefreshTokenService.IssuedRefreshToken refresh = refreshTokenService.issue(
                userEntity.getId(),
                client.getId(),
                UUID.randomUUID(),
                scope,
                String.join(" ", audiences),
                Duration.ofSeconds(client.getRefreshTokenTtl()));
        return new TokenResponse(accessToken, "Bearer", ttl.toSeconds(), refresh.token(), idToken, scope, null);
    }

    public static Duration accessTtl(IamClientEntity client) {
        if (client.getAccessTokenTtl() != null && client.getAccessTokenTtl() > 0) {
            return Duration.ofSeconds(client.getAccessTokenTtl());
        }
        return Duration.ofMinutes(10);
    }

    public static List<String> split(String value) {
        return Arrays.stream(value.trim().split("\\s+")).filter(part -> !part.isBlank()).toList();
    }
}
