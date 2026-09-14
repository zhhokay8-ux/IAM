package com.example.iam.common.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class SecurityRegressionTest {

    @Test
    void masksTokensAndSecretsInLogs() {
        String masked = SensitiveDataMasker.mask(
                "access_token=abc refresh_token=def client_secret=s authorization_code=c Bearer eyJhbGciOiJSUzI1NiJ9.a.b");
        assertFalse(masked.contains("abc"));
        assertFalse(masked.contains("def"));
        assertTrue(masked.contains("***"));
    }

    @Test
    void corsRejectsWildcardAndCredentialsStar() {
        CorsOriginValidator validator = new CorsOriginValidator();
        IamException wildcard = assertThrows(IamException.class, () -> validator.requireAllowed("*", List.of("*")));
        assertEquals(IamErrorCode.INVALID_ORIGIN, wildcard.getErrorCode());
        IamException combo = assertThrows(IamException.class, () -> validator.rejectWildcardAllowOrigin("*", true));
        assertEquals(IamErrorCode.INVALID_ORIGIN, combo.getErrorCode());
        assertTrue(validator.allowed("https://portal.example.com", List.of("https://portal.example.com")));
    }

    @Test
    void csrfAllowsSsoLoginWithoutTokenEvenWithSessionCookie() throws Exception {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigins(List.of("http://localhost:3000"));
        CsrfValidationFilter filter = new CsrfValidationFilter(
                new CsrfTokenService(), new CorsOriginValidator(), properties, "IAM_SSO_SESSION");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/sso/login");
        request.setCookies(new jakarta.servlet.http.Cookie("IAM_SSO_SESSION", "sid"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }

    @Test
    void csrfRejectsCookiePostWithoutToken() throws Exception {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigins(List.of("https://portal.example.com"));
        CsrfValidationFilter filter = new CsrfValidationFilter(
                new CsrfTokenService(), new CorsOriginValidator(), properties, "IAM_SSO_SESSION");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oidc/logout");
        request.setCookies(new jakarta.servlet.http.Cookie("IAM_SSO_SESSION", "sid"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(403, response.getStatus());
    }

    @Test
    void csrfRejectsDisallowedOrigin() throws Exception {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigins(List.of("https://portal.example.com"));
        CsrfValidationFilter filter = new CsrfValidationFilter(
                new CsrfTokenService(), new CorsOriginValidator(), properties, "IAM_SSO_SESSION");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oidc/logout");
        request.setCookies(
                new jakarta.servlet.http.Cookie("IAM_SSO_SESSION", "sid"),
                new jakarta.servlet.http.Cookie(CsrfTokenService.COOKIE, "csrf-1"));
        request.addHeader(CsrfTokenService.HEADER, "csrf-1");
        request.addHeader("Origin", "https://evil.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(400, response.getStatus());
    }

    @Test
    void securityHeadersForbidAllowFromAndSetFrameAncestorsNone() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityHeadersConfig.forPages()
                .doFilter(new MockHttpServletRequest("GET", "/sso/login"), response, new MockFilterChain());
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
        assertFalse(String.valueOf(response.getHeader("X-Frame-Options")).contains("ALLOW-FROM"));
        assertTrue(response.getHeader("Content-Security-Policy").contains("frame-ancestors 'none'"));
    }

    @Test
    void embedHeadersUseParentOriginsAndNeverAllowFrom() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityHeadersConfig.forEmbed(List.of("https://portal.example.com"))
                .doFilter(new MockHttpServletRequest("GET", "/api/embed/code"), response, new MockFilterChain());
        assertTrue(response.getHeader("Content-Security-Policy").contains("https://portal.example.com"));
        assertFalse(String.valueOf(response.getHeader("X-Frame-Options")).contains("ALLOW-FROM"));
        assertFalse("DENY".equals(response.getHeader("X-Frame-Options")));
    }

    @Test
    void tokenLoggingFilterRejectsAccessTokenInQuery() throws Exception {
        TokenLoggingFilter filter = new TokenLoggingFilter();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/callback");
        request.setQueryString("access_token=secret");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(400, response.getStatus());
    }
}
