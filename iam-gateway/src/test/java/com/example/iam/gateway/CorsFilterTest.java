package com.example.iam.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CorsFilterTest {

    private final CorsGatewayFilter filter = new CorsGatewayFilter(List.of("https://portal.example.com"));

    @Test
    void allowsConfiguredOrigin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.addHeader(HttpHeaders.ORIGIN, "https://portal.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals("https://portal.example.com", response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void rejectsWildcardAndUnknownOrigin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.addHeader(HttpHeaders.ORIGIN, "https://evil.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertNull(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        assertEquals(false, filter.allowed("*"));
    }
}
