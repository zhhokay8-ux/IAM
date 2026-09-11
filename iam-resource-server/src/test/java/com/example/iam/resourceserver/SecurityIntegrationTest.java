package com.example.iam.resourceserver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.resourceserver.jwt.TestJwtSupport;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = ResourceServerTestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "iam.resource-server.enabled=true",
            "iam.resource-server.issuer=https://auth.example.com",
            "iam.resource-server.audience=system-n-api",
            "iam.resource-server.permit-all=/api/test/public",
            "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration"
        })
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestJwtSupport jwtSupport;

    @Test
    void publicEndpointAllowsAnonymous() throws Exception {
        mockMvc.perform(get("/api/test/public")).andExpect(status().isOk()).andExpect(content().string("ok"));
    }

    @Test
    void orderEndpointWithoutTokenIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/test/order")).andExpect(status().isUnauthorized());
    }

    @Test
    void orderEndpointWithoutScopeIsForbidden() throws Exception {
        JWTClaimsSet claims = jwtSupport.validClaims().claim("scope", "profile").build();
        mockMvc.perform(get("/api/test/order").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtSupport.token(claims)))
                .andExpect(status().isForbidden());
    }

    @Test
    void orderEndpointWithScopeIsOk() throws Exception {
        mockMvc.perform(get("/api/test/order")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtSupport.token(jwtSupport.validClaims().build())))
                .andExpect(status().isOk())
                .andExpect(content().string("u-100086"));
    }

    @Test
    void orderEndpointWithWrongAudienceIsUnauthorized() throws Exception {
        JWTClaimsSet claims = jwtSupport.validClaims().audience("system-1-api").build();
        mockMvc.perform(get("/api/test/order").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtSupport.token(claims)))
                .andExpect(status().isUnauthorized());
    }
}
