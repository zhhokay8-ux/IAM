package com.example.iam.sdk;

import org.springframework.scheduling.annotation.Scheduled;

public class JwksRefreshScheduler {

    private final IamJwksClient jwksClient;

    public JwksRefreshScheduler(IamJwksClient jwksClient) {
        this.jwksClient = jwksClient;
    }

    @Scheduled(fixedDelayString = "${iam.jwks.refresh:10m}")
    public void refresh() {
        jwksClient.refreshQuietly();
    }
}
