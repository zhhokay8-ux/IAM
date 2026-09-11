package com.example.iam.token.oauth;

public interface IdTokenService {

    String issue(IdTokenClaims claims);
}
