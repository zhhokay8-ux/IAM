package com.example.iam.gateway;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.core.redis.RedisKeyConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.core.Ordered;

public class RateLimitFilter implements IamGatewayFilter {

    private final int limit;
    private final Duration window;
    private final Map<String, Window> counters = new ConcurrentHashMap<>();

    public RateLimitFilter(int limit, Duration window) {
        this.limit = limit <= 0 ? 100 : limit;
        this.window = window == null ? Duration.ofMinutes(1) : window;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 20;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String key = RedisKeyConstants.rateLimit(clientKey(httpRequest));
        if (!allow(key)) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(IamErrorCode.RATE_LIMITED.getHttpStatus());
            httpResponse.setContentType("application/json");
            httpResponse.getWriter()
                    .write("{\"code\":\"" + IamErrorCode.RATE_LIMITED.getCode() + "\",\"message\":\"Too many requests\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    boolean allow(String key) {
        long now = System.currentTimeMillis();
        Window windowState = counters.compute(key, (ignored, current) -> {
            if (current == null || now - current.startedAt >= window.toMillis()) {
                return new Window(now, new AtomicInteger(0));
            }
            return current;
        });
        return windowState.count.incrementAndGet() <= limit;
    }

    String redisKey(String clientId) {
        return RedisKeyConstants.rateLimit(clientId);
    }

    private static String clientKey(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
    }

    private record Window(long startedAt, AtomicInteger count) {
    }
}
