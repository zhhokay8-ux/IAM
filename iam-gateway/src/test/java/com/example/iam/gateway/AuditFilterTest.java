package com.example.iam.gateway;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuditFilterTest {

    @Test
    void recordsMethodPathStatusAndSubject() throws Exception {
        StringBuilder sink = new StringBuilder();
        AuditGatewayFilter filter = new AuditGatewayFilter(sink);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/1");
        request.setAttribute(JwtGatewayFilter.SUBJECT_ATTRIBUTE, "u-100086");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        String event = sink.toString();
        assertTrue(event.contains("method=GET"));
        assertTrue(event.contains("path=/orders/1"));
        assertTrue(event.contains("sub=u-100086"));
        assertTrue(event.contains("status=200"));
    }
}
