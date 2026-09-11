package com.example.iam.authorizationserver.admin.auth;

import com.example.iam.authorizationserver.oidc.logout.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminLoginController {

    private final AdminOAuthLoginService loginService;
    private final LogoutService logoutService;

    public AdminLoginController(AdminOAuthLoginService loginService, LogoutService logoutService) {
        this.loginService = loginService;
        this.logoutService = logoutService;
    }

    @GetMapping("/admin/login")
    public ResponseEntity<Void> login() {
        URI authorize = loginService.startLogin();
        return ResponseEntity.status(HttpStatus.FOUND).location(authorize).build();
    }

    @GetMapping("/admin/callback")
    public ResponseEntity<Void> callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            HttpServletRequest request,
            HttpServletResponse response) {
        URI next = loginService.completeCallback(code, state, error, request, response);
        return ResponseEntity.status(HttpStatus.FOUND).location(next).build();
    }

    @PostMapping("/admin/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        logoutService.logout(request, response, "global");
    }
}
