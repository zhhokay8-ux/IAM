package com.example.iam.embed.repository;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class EmbedCodeRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public EmbedCodeRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String code, String value) {
        save(code, value, properties.getEmbedCodeTtl());
    }

    public void save(String code, String value, Duration ttl) {
        super.save(RedisKeyConstants.embedCode(code), value, ttl);
    }

    public Optional<String> get(String code) {
        return super.get(RedisKeyConstants.embedCode(code));
    }

    public Optional<String> consume(String code) {
        return super.consume(RedisKeyConstants.embedCode(code));
    }

    public Duration getTtl(String code) {
        return getExpire(RedisKeyConstants.embedCode(code));
    }
}
