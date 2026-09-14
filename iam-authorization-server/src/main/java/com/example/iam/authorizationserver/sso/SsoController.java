package com.example.iam.authorizationserver.sso;

import com.example.iam.common.security.CsrfTokenService;
import com.example.iam.session.IamSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SsoController {

    private final SsoAuthenticationService authenticationService;
    private final CsrfTokenService csrfTokenService;

    public SsoController(SsoAuthenticationService authenticationService, CsrfTokenService csrfTokenService) {
        this.authenticationService = authenticationService;
        this.csrfTokenService = csrfTokenService;
    }

    @PostMapping("/sso/login")
    public SsoSessionResponse login(@RequestBody SsoLoginRequest request, HttpServletResponse response) {
        IamSession session = authenticationService.login(request, response);
        return SsoSessionResponse.from(session);
    }

    /**
     * Cross-origin SPAs cannot read the IAM_CSRF cookie; return it in JSON after issuing/refreshing it.
     */
    @GetMapping("/sso/csrf")
    public SsoCsrfResponse csrf(HttpServletRequest request, HttpServletResponse response) {
        return new SsoCsrfResponse(csrfTokenService.ensure(request, response));
    }

    @GetMapping("/sso/session")
    public SsoSessionResponse current(HttpServletRequest request) {
        return SsoSessionResponse.from(authenticationService.requireCurrent(request));
    }
}
