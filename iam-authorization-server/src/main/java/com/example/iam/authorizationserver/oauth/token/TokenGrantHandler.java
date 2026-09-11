package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;

public interface TokenGrantHandler {

    boolean supports(String grantType);

    TokenResponse handle(TokenRequest request, IamClientEntity client);
}
