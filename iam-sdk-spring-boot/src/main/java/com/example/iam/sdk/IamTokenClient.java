package com.example.iam.sdk;

import java.util.Objects;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

public class IamTokenClient {

    private final String tokenUri;
    private final RestClient restClient;

    public IamTokenClient(String issuer) {
        this(issuer, RestClient.create());
    }

    IamTokenClient(String issuer, RestClient restClient) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        this.tokenUri = base + "/oauth2/token";
        this.restClient = Objects.requireNonNull(restClient);
    }

    public String tokenUri() {
        return tokenUri;
    }

    public String clientCredentials(String clientId, String clientSecret, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        if (scope != null && !scope.isBlank()) {
            form.add("scope", scope);
        }
        return restClient
                .post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(String.class);
    }
}
