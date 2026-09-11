package com.example.iam.authorizationserver.oauth.token.exchange;

import com.example.iam.authorizationserver.oauth.token.TokenAuthenticationService;
import com.example.iam.authorizationserver.oauth.token.TokenRequest;
import com.example.iam.authorizationserver.oauth.token.TokenResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenExchangeController {

    public static final String GRANT_TYPE = TokenExchangeServiceImpl.GRANT;

    private final TokenAuthenticationService authenticationService;
    private final TokenExchangeService tokenExchangeService;

    public TokenExchangeController(
            TokenAuthenticationService authenticationService, TokenExchangeService tokenExchangeService) {
        this.authenticationService = authenticationService;
        this.tokenExchangeService = tokenExchangeService;
    }

    @PostMapping(
            path = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            params = "grant_type=" + GRANT_TYPE)
    public TokenResponse exchangeRfc(
            @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "subject_token", required = false) String subjectToken,
            @RequestParam(name = "subject_token_type", required = false) String subjectTokenType,
            @RequestParam(name = "requested_token_type", required = false) String requestedTokenType,
            @RequestParam(name = "audience", required = false) String audience,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "actor_token", required = false) String actorToken,
            @RequestParam(name = "actor_token_type", required = false) String actorTokenType,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {
        return exchange(
                grantType,
                subjectToken,
                subjectTokenType,
                requestedTokenType,
                audience,
                scope,
                actorToken,
                actorTokenType,
                clientId,
                clientSecret,
                httpRequest);
    }

    @PostMapping(
            path = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            params = "grant_type=token-exchange")
    public TokenResponse exchangeAlias(
            @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "subject_token", required = false) String subjectToken,
            @RequestParam(name = "subject_token_type", required = false) String subjectTokenType,
            @RequestParam(name = "requested_token_type", required = false) String requestedTokenType,
            @RequestParam(name = "audience", required = false) String audience,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "actor_token", required = false) String actorToken,
            @RequestParam(name = "actor_token_type", required = false) String actorTokenType,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {
        return exchange(
                grantType,
                subjectToken,
                subjectTokenType,
                requestedTokenType,
                audience,
                scope,
                actorToken,
                actorTokenType,
                clientId,
                clientSecret,
                httpRequest);
    }

    private TokenResponse exchange(
            String grantType,
            String subjectToken,
            String subjectTokenType,
            String requestedTokenType,
            String audience,
            String scope,
            String actorToken,
            String actorTokenType,
            String clientId,
            String clientSecret,
            HttpServletRequest httpRequest) {
        TokenRequest authRequest = new TokenRequest(
                grantType, null, null, null, null, scope, audience, clientId, clientSecret);
        IamClientEntity client = authenticationService.authenticate(httpRequest, authRequest);
        return tokenExchangeService.exchange(
                new TokenExchangeRequest(
                        grantType,
                        subjectToken,
                        subjectTokenType,
                        requestedTokenType,
                        audience,
                        scope,
                        actorToken,
                        actorTokenType),
                client);
    }
}
