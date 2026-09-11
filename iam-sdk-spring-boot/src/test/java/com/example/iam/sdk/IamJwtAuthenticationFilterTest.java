package com.example.iam.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.resourceserver.jwt.AudienceValidator;
import com.example.iam.resourceserver.jwt.IssuerValidator;
import com.example.iam.resourceserver.jwt.JtiValidator;
import com.example.iam.resourceserver.jwt.JwtTokenValidator;
import com.example.iam.resourceserver.jwt.RoleValidator;
import com.example.iam.resourceserver.jwt.ScopeValidator;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class IamJwtAuthenticationFilterTest {

    private SdkTestJwtSupport jwtSupport;
    private IamJwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        jwtSupport = new SdkTestJwtSupport();
        JwtTokenValidator validator = new JwtTokenValidator(
                jwtSupport.resolver(),
                new IssuerValidator(SdkTestJwtSupport.ISSUER),
                new AudienceValidator(SdkTestJwtSupport.AUDIENCE),
                new ScopeValidator(),
                new RoleValidator(),
                new JtiValidator(false, jti -> false),
                Clock.systemUTC(),
                Duration.ofSeconds(30));
        filter = new IamJwtAuthenticationFilter(validator, new String[] {"/public/**"});
    }

    @AfterEach
    void tearDown() {
        IamUserContextHolder.clear();
    }

    @Test
    void validBearerPopulatesUserContextDuringChain() throws Exception {
        AtomicReference<IamUserContext> seen = new AtomicReference<>();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/1");
        request.addHeader("Authorization", "Bearer " + jwtSupport.token(jwtSupport.validClaims().build()));
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> seen.set(IamUserContextHolder.get()));
        assertEquals("u-100086", seen.get().getSubject());
        assertTrue(seen.get().getScopes().contains("order.read"));
        assertEquals("system-1", seen.get().getClientId());
    }

    @Test
    void missingTokenIsUnauthorized() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/orders/1"), response, new MockFilterChain());
        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains(IamErrorCode.UNAUTHORIZED.getCode()));
    }

    @Test
    void permitAllSkipsJwt() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/public/health"), response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }
}
