package com.example.iam.authorizationserver.oauth.revoke;

public interface TokenRevocationService {

    boolean revoke(String token, String tokenTypeHint);
}
