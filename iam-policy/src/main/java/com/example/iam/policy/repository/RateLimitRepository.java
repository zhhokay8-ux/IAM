package com.example.iam.policy.repository;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RateLimitRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public RateLimitRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public long increment(String key) {
        String redisKey = RedisKeyConstants.rateLimit(key);
        Long count = redisTemplate.opsForValue().increment(redisKey);
        if (count != null && count == 1L) {
            redisTemplate.expire(redisKey, properties.getRateLimitTtl());
        }
        return count == null ? 0L : count;
    }

    public Duration getTtl(String key) {
        return getExpire(RedisKeyConstants.rateLimit(key));
    }
}
