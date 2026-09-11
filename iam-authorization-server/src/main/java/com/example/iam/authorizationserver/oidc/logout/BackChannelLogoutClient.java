package com.example.iam.authorizationserver.oidc.logout;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

@Component
public class BackChannelLogoutClient {

    private static final Logger log = LoggerFactory.getLogger(BackChannelLogoutClient.class);

    private final RestClient restClient;

    public BackChannelLogoutClient() {
        this(RestClient.create());
    }

    BackChannelLogoutClient(RestClient restClient) {
        this.restClient = Objects.requireNonNull(restClient, "restClient");
    }

    public void postLogoutToken(String uri, String logoutToken) {
        if (uri == null || uri.isBlank() || logoutToken == null || logoutToken.isBlank()) {
            return;
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("logout_token", logoutToken);
        try {
            restClient
                    .post()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException ex) {
            log.warn("back-channel logout POST failed uri={}", uri, ex);
        }
    }

    static String formBody(String logoutToken) {
        return "logout_token=" + java.net.URLEncoder.encode(logoutToken, StandardCharsets.UTF_8);
    }
}
