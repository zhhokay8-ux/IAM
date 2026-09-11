package com.example.iam.authorizationserver.oauth;

public interface AuthorizationService {

    AuthorizationResponse authorize(AuthorizationRequest request, String subject);
}
