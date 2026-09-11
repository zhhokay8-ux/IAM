package com.example.iam.authorizationserver.oidc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class OidcDiscoveryControllerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        OidcDiscoveryService service = new OidcDiscoveryService("https://auth.example.com");
        mockMvc = MockMvcBuilders.standaloneSetup(new OidcDiscoveryController(service)).build();
    }

    @Test
    void returnsOidcDiscoveryDocument() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://auth.example.com"))
                .andExpect(jsonPath("$.authorization_endpoint").value("https://auth.example.com/oauth2/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value("https://auth.example.com/oauth2/token"))
                .andExpect(jsonPath("$.jwks_uri").value("https://auth.example.com/.well-known/jwks.json"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("https://auth.example.com/oidc/userinfo"))
                .andExpect(jsonPath("$.revocation_endpoint").value("https://auth.example.com/oauth2/revoke"))
                .andExpect(jsonPath("$.introspection_endpoint").value("https://auth.example.com/oauth2/introspect"))
                .andExpect(jsonPath("$.end_session_endpoint").value("https://auth.example.com/oidc/logout"))
                .andExpect(jsonPath("$.backchannel_logout_endpoint")
                        .value("https://auth.example.com/oidc/backchannel-logout"))
                .andExpect(jsonPath("$.response_types_supported[0]").value("code"))
                .andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
                .andExpect(jsonPath("$.grant_types_supported", Matchers.hasItems(
                        "authorization_code",
                        "refresh_token",
                        "client_credentials",
                        "urn:ietf:params:oauth:grant-type:token-exchange")));
    }
}
