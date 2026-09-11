package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class TokenAuthenticationService {

    private final ClientAuthenticationProvider clientAuthenticationProvider;

    public TokenAuthenticationService(ClientAuthenticationProvider clientAuthenticationProvider) {
        this.clientAuthenticationProvider = clientAuthenticationProvider;
    }

    public IamClientEntity authenticate(HttpServletRequest httpRequest, TokenRequest request) {
        return clientAuthenticationProvider.authenticate(httpRequest, request);
    }

    public IamClientEntity authenticate(String clientId, String secret) {
        return clientAuthenticationProvider.authenticate(clientId, secret);
    }
}
