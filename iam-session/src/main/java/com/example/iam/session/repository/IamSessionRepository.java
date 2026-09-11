package com.example.iam.session.repository;

import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.IamRedisRepository;
import com.example.iam.core.redis.RedisKeyConstants;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class IamSessionRepository extends IamRedisRepository {

    private final IamRedisProperties properties;

    public IamSessionRepository(StringRedisTemplate redisTemplate, IamRedisProperties properties) {
        super(redisTemplate);
        this.properties = properties;
    }

    public void save(String sessionId, String value) {
        save(RedisKeyConstants.session(sessionId), value, properties.getSessionTtl());
    }

    public void save(String sessionId, String value, Duration ttl) {
        super.save(RedisKeyConstants.session(sessionId), value, ttl);
    }

    public Optional<String> get(String sessionId) {
        return super.get(RedisKeyConstants.session(sessionId));
    }

    public boolean delete(String sessionId) {
        return super.delete(RedisKeyConstants.session(sessionId));
    }

    public Duration getTtl(String sessionId) {
        return getExpire(RedisKeyConstants.session(sessionId));
    }

    public void indexSubject(String subjectId, String sessionId, Duration ttl) {
        if (subjectId == null || subjectId.isBlank() || sessionId == null || sessionId.isBlank()) {
            return;
        }
        String key = RedisKeyConstants.sessionSubject(subjectId);
        redisTemplate.opsForSet().add(key, sessionId);
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            redisTemplate.expire(key, ttl);
        }
    }

    public void removeSubjectIndex(String subjectId, String sessionId) {
        if (subjectId == null || subjectId.isBlank() || sessionId == null || sessionId.isBlank()) {
            return;
        }
        redisTemplate.opsForSet().remove(RedisKeyConstants.sessionSubject(subjectId), sessionId);
    }

    public Set<String> listSidsBySubject(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            return Set.of();
        }
        Set<String> members = redisTemplate.opsForSet().members(RedisKeyConstants.sessionSubject(subjectId));
        return members == null ? Collections.emptySet() : members;
    }

    public Optional<String> getRaw(String key) {
        return super.get(key);
    }

    public void saveRaw(String key, String value, Duration ttl) {
        super.save(key, value, ttl);
    }

    /**
     * SCAN {@code session:*} excluding {@code session:subject:*} indexes. Caps work per dashboard call.
     */
    public List<String> scanSessionSids(int cap) {
        int limit = Math.max(cap, 1);
        List<String> sids = new ArrayList<>();
        ScanOptions options = ScanOptions.scanOptions().match(RedisKeyConstants.SESSION + "*").count(200).build();
        try (Cursor<String> cursor = redisTemplate.scan(options)) {
            while (cursor.hasNext()) {
                String key = cursor.next();
                if (!RedisKeyConstants.isSessionPayloadKey(key)) {
                    continue;
                }
                sids.add(key.substring(RedisKeyConstants.SESSION.length()));
                if (sids.size() >= limit) {
                    break;
                }
            }
        }
        return sids;
    }
}
