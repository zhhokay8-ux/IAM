package com.example.iam.token.oauth;

public interface AccessTokenService {

    String issue(AccessTokenClaims claims);
}
