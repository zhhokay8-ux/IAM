package com.example.iam.authorizationserver.oidc.logout;

import com.nimbusds.jwt.JWTClaimsSet;

public interface BackChannelLogoutService {

    void notifyClients(String subjectId, String sessionId);

    String issueLogoutToken(String audienceClientId, String subjectId, String sessionId);

    JWTClaimsSet consumeLogoutToken(String logoutToken);
}
