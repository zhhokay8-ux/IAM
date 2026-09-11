package com.example.iam.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RateLimitFilterTest {

    @Test
    void usesRateLimitRedisKeyPrefix() {
        RateLimitFilter filter = new RateLimitFilter(2, Duration.ofMinutes(1));
        assertEquals(RedisKeyConstants.rateLimit("1.1.1.1"), filter.redisKey("1.1.1.1"));
    }

    @Test
    void rejectsWhenLimitExceeded() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(1, Duration.ofMinutes(1));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.setRemoteAddr("10.0.0.8");
        MockHttpServletResponse first = new MockHttpServletResponse();
        filter.doFilter(request, first, new MockFilterChain());
        assertEquals(200, first.getStatus());
        MockHttpServletResponse second = new MockHttpServletResponse();
        filter.doFilter(request, second, new MockFilterChain());
        assertEquals(429, second.getStatus());
        assertTrue(second.getContentAsString().contains(IamErrorCode.RATE_LIMITED.getCode()));
    }
}
