package com.example.iam.authorizationserver.oauth.revoke;

import com.example.iam.authorizationserver.oauth.token.ClientAuthenticationProvider;
import com.example.iam.authorizationserver.oauth.token.TokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenRevocationController {

    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final TokenRevocationService tokenRevocationService;

    public TokenRevocationController(
            ClientAuthenticationProvider clientAuthenticationProvider,
            TokenRevocationService tokenRevocationService) {
        this.clientAuthenticationProvider = clientAuthenticationProvider;
        this.tokenRevocationService = tokenRevocationService;
    }

    @PostMapping(path = "/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(
            @RequestParam(name = "token", required = false) String token,
            @RequestParam(name = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {
        clientAuthenticationProvider.authenticate(
                httpRequest, new TokenRequest(null, null, null, null, null, null, null, clientId, clientSecret));
        tokenRevocationService.revoke(token, tokenTypeHint);
    }
}
