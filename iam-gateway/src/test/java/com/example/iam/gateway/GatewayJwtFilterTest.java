package com.example.iam.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class GatewayJwtFilterTest {

    private final GatewayTestJwt jwt = new GatewayTestJwt();
    private final JwtGatewayFilter filter =
            new JwtGatewayFilter(jwt.resolver(), GatewayTestJwt.ISSUER, Duration.ofSeconds(30), new String[] {"/health"});

    @Test
    void firstPassAcceptsValidTokenWithoutCheckingScope() throws Exception {
        MockHttpServletRequest request = bearer(jwt.validClaims().claim("scope", "none").build());
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(200, response.getStatus());
        assertEquals("u-100086", request.getAttribute(JwtGatewayFilter.SUBJECT_ATTRIBUTE));
    }

    @Test
    void firstPassDoesNotEnforceAudience() throws Exception {
        MockHttpServletRequest request = bearer(jwt.validClaims().audience("other-api").build());
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        JWTClaimsSet claims = jwt.validClaims().expirationTime(Date.from(Instant.now().minusSeconds(120))).build();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(bearer(claims), response, new MockFilterChain());
        assertEquals(401, response.getStatus());
        assertNull(new MockHttpServletRequest().getAttribute(JwtGatewayFilter.SUBJECT_ATTRIBUTE));
    }

    @Test
    void missingTokenIsUnauthorized() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/orders"), response, new MockFilterChain());
        assertEquals(401, response.getStatus());
    }

    private MockHttpServletRequest bearer(JWTClaimsSet claims) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("Authorization", "Bearer " + jwt.token(claims));
        return request;
    }
}
