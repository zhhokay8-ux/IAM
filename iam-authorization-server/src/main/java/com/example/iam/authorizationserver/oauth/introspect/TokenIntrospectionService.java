package com.example.iam.authorizationserver.oauth.introspect;

public interface TokenIntrospectionService {

    TokenIntrospectionResponse introspect(String token);
}
