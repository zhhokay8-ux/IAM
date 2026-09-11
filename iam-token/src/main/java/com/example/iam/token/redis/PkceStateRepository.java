package com.example.iam.token.redis;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class PkceStateRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public PkceStateRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String value, String payload) {
        save(RedisKeyConstants.pkceState(value), payload, properties.getPkceStateTtl());
    }

    public Optional<String> get(String value) {
        return super.get(RedisKeyConstants.pkceState(value));
    }

    public boolean delete(String value) {
        return super.delete(RedisKeyConstants.pkceState(value));
    }

    public Duration getTtl(String value) {
        return getExpire(RedisKeyConstants.pkceState(value));
    }
}
