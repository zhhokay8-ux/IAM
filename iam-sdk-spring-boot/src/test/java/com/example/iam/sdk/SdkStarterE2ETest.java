package com.example.iam.sdk;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(classes = SdkStarterE2ETest.App.class)
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "iam.issuer=https://auth.example.com",
            "iam.resource-server.audience=system-n-api",
            "iam.jwks.cache-ttl=1h",
            "iam.token.clock-skew=30s"
        })
class SdkStarterE2ETest {

    static final SdkTestJwtSupport JWT = new SdkTestJwtSupport();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void starterSecuresBusinessEndpointWithRequireScope() throws Exception {
        mockMvc.perform(get("/orders/1")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/orders/1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + JWT.token(JWT.validClaims().build())))
                .andExpect(status().isOk())
                .andExpect(content().string("u-100086"));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude = {RedisAutoConfiguration.class, DataSourceAutoConfiguration.class})
    static class App {
        @Bean
        IamJwksClient iamJwksClient() {
            return IamJwksClient.staticSet(new JWKSet(JWT.rsaJwk()));
        }

        @RestController
        static class Orders {
            @RequireScope("order.read")
            @GetMapping("/orders/1")
            String get() {
                return IamUserContextHolder.require().getSubject();
            }
        }
    }
}
