package com.example.iam.policy;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class TokenExchangePolicyServiceImpl implements TokenExchangePolicyService {

    private final IamPolicyEvaluator policyEvaluator;

    public TokenExchangePolicyServiceImpl(IamPolicyEvaluator policyEvaluator) {
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public void requireRequestedAudience(String audience) {
        if (audience == null || audience.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "audience is required");
        }
        policyEvaluator.validateAudience(audience);
    }

    @Override
    public void requireExchangePermission(String clientId, String audience, List<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        for (String scope : scopes) {
            policyEvaluator.validateTokenExchangePermission(clientId, audience, scope);
        }
    }

    @Override
    public void requireActorAuthorized(String actorClientId, String callingClientId) {
        if (actorClientId == null || actorClientId.isBlank() || callingClientId == null || callingClientId.isBlank()) {
            throw new IamException(IamErrorCode.ACTOR_UNAUTHORIZED, "actor is not authorized");
        }
        if (!callingClientId.equals(actorClientId)) {
            throw new IamException(IamErrorCode.ACTOR_UNAUTHORIZED, "actor is not authorized");
        }
    }
}
