package com.example.iam.migration.repository;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class MigrationTicketRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public MigrationTicketRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String ticket, String value) {
        save(ticket, value, properties.getMigrationTicketTtl());
    }

    public void save(String ticket, String value, Duration ttl) {
        save(RedisKeyConstants.migrationTicket(ticket), value, ttl);
    }

    public Optional<String> get(String ticket) {
        return super.get(RedisKeyConstants.migrationTicket(ticket));
    }

    public Optional<String> consume(String ticket) {
        return super.consume(RedisKeyConstants.migrationTicket(ticket));
    }

    public Duration getTtl(String ticket) {
        return getExpire(RedisKeyConstants.migrationTicket(ticket));
    }
}
