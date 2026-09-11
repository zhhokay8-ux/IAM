package com.example.iam.authorizationserver.oauth;

import com.example.iam.authorizationserver.sso.SsoAuthenticationService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthorizationController {

    public static final String SESSION_COOKIE = SsoCookieService.COOKIE_NAME;

    private final AuthorizationService authorizationService;
    private final SsoAuthenticationService ssoAuthenticationService;

    public AuthorizationController(
            AuthorizationService authorizationService, SsoAuthenticationService ssoAuthenticationService) {
        this.authorizationService = authorizationService;
        this.ssoAuthenticationService = ssoAuthenticationService;
    }

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "nonce", required = false) String nonce,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            HttpServletRequest httpRequest) {
        AuthorizationRequest request = new AuthorizationRequest(
                clientId,
                redirectUri,
                responseType,
                scope,
                state,
                nonce,
                codeChallenge,
                codeChallengeMethod);
        URI location = authorizationService
                .authorize(request, ssoAuthenticationService.subjectFromRequest(httpRequest))
                .redirectLocation();
        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
    }
}
