package com.example.iam.authorizationserver.oauth.introspect;

import com.example.iam.authorizationserver.oauth.token.ClientAuthenticationProvider;
import com.example.iam.authorizationserver.oauth.token.TokenRequest;
import com.example.iam.clientregistry.entity.IamClientEntity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenIntrospectionController {

    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final TokenIntrospectionService tokenIntrospectionService;

    public TokenIntrospectionController(
            ClientAuthenticationProvider clientAuthenticationProvider,
            TokenIntrospectionService tokenIntrospectionService) {
        this.clientAuthenticationProvider = clientAuthenticationProvider;
        this.tokenIntrospectionService = tokenIntrospectionService;
    }

    @PostMapping(path = "/oauth2/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenIntrospectionResponse introspect(
            @RequestParam(name = "token", required = false) String token,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {
        IamClientEntity client = clientAuthenticationProvider.authenticate(
                httpRequest, new TokenRequest(null, null, null, null, null, null, null, clientId, clientSecret));
        ClientAuthenticationProvider.requireConfidential(client);
        return tokenIntrospectionService.introspect(token);
    }
}
