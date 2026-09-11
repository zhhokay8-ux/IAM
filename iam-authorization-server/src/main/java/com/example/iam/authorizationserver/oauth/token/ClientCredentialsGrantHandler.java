package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import java.time.Duration;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class ClientCredentialsGrantHandler implements TokenGrantHandler {

    private final IamPolicyEvaluator policyEvaluator;
    private final ServiceTokenService serviceTokenService;

    public ClientCredentialsGrantHandler(
            IamPolicyEvaluator policyEvaluator, ServiceTokenService serviceTokenService) {
        this.policyEvaluator = policyEvaluator;
        this.serviceTokenService = serviceTokenService;
    }

    @Override
    public boolean supports(String grantType) {
        return "client_credentials".equals(grantType);
    }

    @Override
    public TokenResponse handle(TokenRequest request, IamClientEntity client) {
        ClientAuthenticationProvider.requireConfidential(client);
        if (request.scope() == null || request.scope().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        List<String> scopes = AuthorizationCodeTokenGrantHandler.split(request.scope());
        List<String> audiences = resolveAudiences(request, client, scopes);
        String scope = String.join(" ", scopes);
        String accessToken = serviceTokenService.issue(client, audiences, scope);
        Duration ttl = AuthorizationCodeTokenGrantHandler.accessTtl(client);
        return new TokenResponse(accessToken, "Bearer", ttl.toSeconds(), null, null, scope, null);
    }

    private List<String> resolveAudiences(TokenRequest request, IamClientEntity client, List<String> scopes) {
        try {
            if (request.audience() != null && !request.audience().isBlank()) {
                for (String scopeCode : scopes) {
                    policyEvaluator.validateClientCredentialsPermission(
                            client.getClientId(), request.audience(), scopeCode);
                }
                return List.of(request.audience());
            }
            return policyEvaluator.resolveAudiences(client.getClientId(), scopes, GrantType.CLIENT_CREDENTIALS);
        } catch (IamException ex) {
            throw switch (ex.getErrorCode()) {
                case SCOPE_NOT_FOUND, SCOPE_NOT_BOUND, SCOPE_INACTIVE, AUDIENCE_NOT_FOUND,
                        CLIENT_CREDENTIALS_NOT_ALLOWED -> new IamException(
                        IamErrorCode.PERMISSION_DENIED, ex.getMessage());
                default -> ex;
            };
        }
    }
}
