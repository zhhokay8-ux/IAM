package com.example.iam.token.redis;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class OAuthStateRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public OAuthStateRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String value, String payload) {
        save(RedisKeyConstants.oauthState(value), payload, properties.getOauthStateTtl());
    }

    public Optional<String> get(String value) {
        return super.get(RedisKeyConstants.oauthState(value));
    }

    public Optional<String> consume(String value) {
        return super.consume(RedisKeyConstants.oauthState(value));
    }

    public Duration getTtl(String value) {
        return getExpire(RedisKeyConstants.oauthState(value));
    }
}
