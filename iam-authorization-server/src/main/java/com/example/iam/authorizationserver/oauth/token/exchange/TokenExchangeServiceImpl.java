package com.example.iam.authorizationserver.oauth.token.exchange;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.token.AuthorizationCodeTokenGrantHandler;
import com.example.iam.authorizationserver.oauth.token.TokenResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.TokenExchangePolicyService;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.service.IamUserService;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class TokenExchangeServiceImpl implements TokenExchangeService {

    static final String GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = SubjectTokenValidator.ACCESS_TOKEN_TYPE;

    private final SubjectTokenValidator subjectTokenValidator;
    private final ActorTokenValidator actorTokenValidator;
    private final TokenExchangePolicyService policyService;
    private final AccessTokenService accessTokenService;
    private final IamUserService userService;
    private final IamAuditService auditService;

    public TokenExchangeServiceImpl(
            SubjectTokenValidator subjectTokenValidator,
            ActorTokenValidator actorTokenValidator,
            TokenExchangePolicyService policyService,
            AccessTokenService accessTokenService,
            IamUserService userService,
            IamAuditService auditService) {
        this.subjectTokenValidator = subjectTokenValidator;
        this.actorTokenValidator = actorTokenValidator;
        this.policyService = policyService;
        this.accessTokenService = accessTokenService;
        this.userService = userService;
        this.auditService = auditService;
    }

    @Override
    public TokenResponse exchange(TokenExchangeRequest request, IamClientEntity client) {
        if (request == null || client == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "token exchange request is required");
        }
        assertGrant(request.grantType());
        assertRequestedTokenType(request.requestedTokenType());
        policyService.requireRequestedAudience(request.audience());
        DelegationContext subject = subjectTokenValidator.validate(request.subjectToken(), request.subjectTokenType());
        if (subject.clientId() != null
                && !subject.clientId().isBlank()
                && !client.getClientId().equals(subject.clientId())) {
            throw new IamException(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, "subject token was not issued to this client");
        }
        ActorContext actor = null;
        if (request.actorToken() != null && !request.actorToken().isBlank()) {
            actor = actorTokenValidator.validate(request.actorToken(), request.actorTokenType());
            policyService.requireActorAuthorized(actor.clientId(), client.getClientId());
        }
        List<String> scopes = resolveScopes(request.scope());
        policyService.requireExchangePermission(client.getClientId(), request.audience(), scopes);

        Instant now = Instant.now();
        Duration ttl = AuthorizationCodeTokenGrantHandler.accessTtl(client);
        String scope = String.join(" ", scopes);
        String tenantId = subject.tenantId();
        String orgId = subject.orgId();
        try {
            UUID subjectId = UUID.fromString(subject.subject());
            UserContext user = userService.requireActiveForToken(subjectId);
            tenantId = user.tenantId();
            orgId = user.orgId();
        } catch (IllegalArgumentException ignored) {
            // non-UUID subjects keep claims from the subject token
        }
        String accessToken = accessTokenService.issue(new AccessTokenClaims(
                subject.subject(),
                List.of(request.audience()),
                client.getClientId(),
                scope,
                subject.roles() == null ? List.of() : subject.roles(),
                tenantId,
                orgId,
                now,
                now.plus(ttl),
                null,
                actor == null ? null : actor.subject(),
                null));
        auditService.success(
                AuditEvent.TOKEN_EXCHANGE,
                subject.subject(),
                client.getClientId(),
                "original_sub=" + subject.subject()
                        + "; calling_client=" + client.getClientId()
                        + "; target_resource=" + request.audience()
                        + "; scope=" + scope
                        + "; jti=" + subject.jti());
        return new TokenResponse(
                accessToken, "Bearer", ttl.toSeconds(), null, null, scope, ACCESS_TOKEN_TYPE);
    }

    private static void assertGrant(String grantType) {
        if (grantType == null || grantType.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "grant_type is required");
        }
        if (!GRANT.equals(grantType) && !"token-exchange".equals(grantType)) {
            throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "unsupported grant_type: " + grantType);
        }
    }

    private static void assertRequestedTokenType(String requestedTokenType) {
        if (requestedTokenType == null || requestedTokenType.isBlank()) {
            return;
        }
        if (!ACCESS_TOKEN_TYPE.equals(requestedTokenType.trim())
                && !"urn:ietf:params:oauth:token-type:jwt".equals(requestedTokenType.trim())) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "unsupported requested_token_type");
        }
    }

    private static List<String> resolveScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        return AuthorizationCodeTokenGrantHandler.split(scope);
    }
}
