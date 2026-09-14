package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenController {

    private final TokenAuthenticationService authenticationService;
    private final TokenService tokenService;

    public TokenController(TokenAuthenticationService authenticationService, TokenService tokenService) {
        this.authenticationService = authenticationService;
        this.tokenService = tokenService;
    }

    @PostMapping(
            path = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            params = {
                "grant_type!=urn:ietf:params:oauth:grant-type:token-exchange",
                "grant_type!=token-exchange"
            })
    public TokenResponse token(
            @RequestParam(name = "grant_type", required = false) String grantType,
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "code_verifier", required = false) String codeVerifier,
            @RequestParam(name = "refresh_token", required = false) String refreshToken,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "audience", required = false) String audience,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {
        TokenRequest request = new TokenRequest(
                grantType,
                code,
                redirectUri,
                codeVerifier,
                refreshToken,
                scope,
                audience,
                clientId,
                clientSecret);
        IamClientEntity client = authenticationService.authenticate(httpRequest, request);
        return tokenService.issue(request, client);
    }
}
