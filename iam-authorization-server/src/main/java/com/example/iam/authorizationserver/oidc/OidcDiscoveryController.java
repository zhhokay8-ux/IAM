package com.example.iam.authorizationserver.oidc;

import java.time.Duration;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OidcDiscoveryController {

    private final OidcDiscoveryService discoveryService;

    public OidcDiscoveryController(OidcDiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    @GetMapping(path = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OidcDiscoveryResponse> openidConfiguration() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(discoveryService.discovery());
    }
}
