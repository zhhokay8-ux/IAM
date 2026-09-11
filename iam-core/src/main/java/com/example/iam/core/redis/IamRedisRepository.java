package com.example.iam.core.redis;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

public abstract class IamRedisRepository {

    /**
     * GET+DEL in one script. Avoids {@code GETDEL} (Redis 6.2+); works on Redis 2.6+.
     */
    private static final DefaultRedisScript<String> CONSUME_ONCE = new DefaultRedisScript<>(
            "local v = redis.call('GET', KEYS[1]) if v ~= nil then redis.call('DEL', KEYS[1]) end return v",
            String.class);

    protected final StringRedisTemplate redisTemplate;

    protected IamRedisRepository(StringRedisTemplate redisTemplate) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
    }

    protected void save(String key, String value, Duration ttl) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        redisTemplate.opsForValue().set(key, value, ttl);
    }

    protected Optional<String> get(String key) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(Objects.requireNonNull(key, "key")));
    }

    protected boolean delete(String key) {
        return Boolean.TRUE.equals(redisTemplate.delete(Objects.requireNonNull(key, "key")));
    }

    protected Optional<String> consume(String key) {
        String value = redisTemplate.execute(CONSUME_ONCE, List.of(Objects.requireNonNull(key, "key")));
        return Optional.ofNullable(value);
    }

    protected Duration getExpire(String key) {
        Long seconds = redisTemplate.getExpire(Objects.requireNonNull(key, "key"));
        return seconds == null ? Duration.ZERO : Duration.ofSeconds(seconds);
    }
}
