package com.example.iam.authorizationserver.oidc.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogoutController {

    private final LogoutService logoutService;
    private final BackChannelLogoutService backChannelLogoutService;

    public LogoutController(LogoutService logoutService, BackChannelLogoutService backChannelLogoutService) {
        this.logoutService = logoutService;
        this.backChannelLogoutService = backChannelLogoutService;
    }

    @GetMapping("/oidc/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logoutGet(
            @RequestParam(name = "logout_type", required = false) String logoutType,
            HttpServletRequest request,
            HttpServletResponse response) {
        logoutService.logout(request, response, logoutType);
    }

    @PostMapping(path = "/oidc/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logoutPost(
            @RequestParam(name = "logout_type", required = false) String logoutType,
            HttpServletRequest request,
            HttpServletResponse response) {
        logoutService.logout(request, response, logoutType);
    }

    @PostMapping(path = "/oidc/backchannel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void backChannelLogout(@RequestParam(name = "logout_token", required = false) String logoutToken) {
        backChannelLogoutService.consumeLogoutToken(logoutToken);
    }
}
