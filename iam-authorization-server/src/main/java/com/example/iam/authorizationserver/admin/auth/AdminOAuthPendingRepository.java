package com.example.iam.authorizationserver.admin.auth;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AdminOAuthPendingRepository extends IamRedisRepository {

    private final IamRedisProperties properties;
    private final ObjectMapper objectMapper;

    public AdminOAuthPendingRepository(
            StringRedisTemplate redisTemplate, IamRedisProperties properties, ObjectMapper objectMapper) {
        super(redisTemplate);
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public void save(AdminOAuthPending pending) {
        try {
            save(
                    RedisKeyConstants.adminOauth(pending.state()),
                    objectMapper.writeValueAsString(pending),
                    properties.getOauthStateTtl());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to serialize admin OAuth pending state", ex);
        }
    }

    public Optional<AdminOAuthPending> consumePending(String state) {
        if (state == null || state.isBlank()) {
            return Optional.empty();
        }
        return super.consume(RedisKeyConstants.adminOauth(state)).map(this::read);
    }

    public Optional<AdminOAuthPending> findPending(String state) {
        if (state == null || state.isBlank()) {
            return Optional.empty();
        }
        return super.get(RedisKeyConstants.adminOauth(state)).map(this::read);
    }

    private AdminOAuthPending read(String json) {
        try {
            return objectMapper.readValue(json, AdminOAuthPending.class);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to parse admin OAuth pending state", ex);
        }
    }
}
