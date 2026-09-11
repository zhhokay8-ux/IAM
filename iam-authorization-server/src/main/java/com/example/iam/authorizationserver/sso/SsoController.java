package com.example.iam.authorizationserver.sso;

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

    public SsoController(SsoAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/sso/login")
    public SsoSessionResponse login(@RequestBody SsoLoginRequest request, HttpServletResponse response) {
        IamSession session = authenticationService.login(request, response);
        return SsoSessionResponse.from(session);
    }

    @GetMapping("/sso/session")
    public SsoSessionResponse current(HttpServletRequest request) {
        return SsoSessionResponse.from(authenticationService.requireCurrent(request));
    }
}
