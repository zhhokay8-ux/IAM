package com.example.iam.gateway;

import com.example.iam.common.trace.TraceId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.web.util.ContentCachingResponseWrapper;

public class AuditGatewayFilter implements IamGatewayFilter {

    private static final Logger log = LoggerFactory.getLogger(AuditGatewayFilter.class);

    private final StringBuilder sink;

    public AuditGatewayFilter() {
        this(null);
    }

    AuditGatewayFilter(StringBuilder sink) {
        this.sink = sink;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 40;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        ContentCachingResponseWrapper wrapped = new ContentCachingResponseWrapper(httpResponse);
        try {
            chain.doFilter(request, wrapped);
        } finally {
            String event = "requestId="
                    + TraceId.current()
                    + " method="
                    + httpRequest.getMethod()
                    + " path="
                    + httpRequest.getRequestURI()
                    + " sub="
                    + httpRequest.getAttribute(JwtGatewayFilter.SUBJECT_ATTRIBUTE)
                    + " status="
                    + wrapped.getStatus();
            log.info("gateway.audit {}", event);
            if (sink != null) {
                sink.append(event);
            }
            wrapped.copyBodyToResponse();
        }
    }
}
