package com.example.iam.token.redis;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenStatusRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public RefreshTokenStatusRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String tokenHash, String status) {
        save(RedisKeyConstants.refreshTokenStatus(tokenHash), status,
                properties.getRefreshTokenStatusTtl());
    }

    public Optional<String> get(String tokenHash) {
        return super.get(RedisKeyConstants.refreshTokenStatus(tokenHash));
    }

    public void revoke(String tokenHash) {
        save(tokenHash, "REVOKED");
    }

    public boolean isRevoked(String tokenHash) {
        return get(tokenHash).filter("REVOKED"::equals).isPresent();
    }

    public Duration getTtl(String tokenHash) {
        return getExpire(RedisKeyConstants.refreshTokenStatus(tokenHash));
    }
}
