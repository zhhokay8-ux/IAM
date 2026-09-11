package com.example.iam.gateway;

import com.example.iam.common.trace.TraceId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;

public class RequestIdFilter implements IamGatewayFilter {

    public static final String HEADER = "X-Request-Id";

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestId = httpRequest.getHeader(HEADER);
        if (requestId == null || requestId.isBlank()) {
            requestId = TraceId.newValue();
        }
        TraceId.put(requestId);
        httpResponse.setHeader(HEADER, requestId);
        try {
            chain.doFilter(request, response);
        } finally {
            TraceId.clear();
        }
    }
}
