package com.example.iam.policy;

import java.util.List;

public interface TokenExchangePolicyService {

    void requireRequestedAudience(String audience);

    void requireExchangePermission(String clientId, String audience, List<String> scopes);

    void requireActorAuthorized(String actorClientId, String callingClientId);
}
