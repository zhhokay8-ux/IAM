package com.example.iam.token.oauth;

import java.util.Optional;

public interface AuthorizationCodeService {

    String issue(AuthorizationCodePayload payload);

    Optional<AuthorizationCodePayload> find(String code);

    AuthorizationCodePayload consume(String code, String clientId, String redirectUri);
}
