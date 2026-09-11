package com.example.iam.token.redis;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RevokedJtiRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public RevokedJtiRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void revoke(String jti) {
        revoke(jti, properties.getRevokedJtiTtl());
    }

    public void revoke(String jti, Duration ttl) {
        Duration effective = ttl == null || ttl.isZero() || ttl.isNegative()
                ? properties.getRevokedJtiTtl()
                : ttl;
        save(RedisKeyConstants.revokedJti(jti), "1", effective);
    }

    public boolean isRevoked(String jti) {
        return super.get(RedisKeyConstants.revokedJti(jti)).isPresent();
    }

    public Duration getTtl(String jti) {
        return getExpire(RedisKeyConstants.revokedJti(jti));
    }
}
