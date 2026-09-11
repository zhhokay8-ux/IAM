package com.example.iam.session;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.core.redis.RedisKeyConstants;
import com.example.iam.session.repository.IamSessionRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class IamSessionServiceImpl implements IamSessionService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final IamSessionRepository repository;
    private final IamRedisProperties properties;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public IamSessionServiceImpl(
            IamSessionRepository repository, IamRedisProperties properties, ObjectMapper objectMapper) {
        this(repository, properties, objectMapper, Clock.systemUTC());
    }

    IamSessionServiceImpl(
            IamSessionRepository repository,
            IamRedisProperties properties,
            ObjectMapper objectMapper,
            Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public IamSession create(String subjectId, String clientId, String authenticationLevel) {
        if (subjectId == null || subjectId.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "subject_id is required");
        }
        Instant now = clock.instant();
        Duration ttl = ttl();
        IamSession session = new IamSession(
                randomSid(),
                subjectId,
                now,
                now,
                now.plus(ttl),
                authenticationLevel == null || authenticationLevel.isBlank() ? "pwd" : authenticationLevel,
                clientId,
                IamSession.STATUS_ACTIVE);
        repository.save(session.sid(), write(session), ttl);
        repository.indexSubject(subjectId, session.sid(), ttl);
        return session;
    }

    @Override
    public IamSession require(String sid) {
        return find(sid).orElseThrow(() -> new IamException(IamErrorCode.SESSION_NOT_FOUND, "SSO session not found"));
    }

    @Override
    public Optional<IamSession> find(String sid) {
        if (sid == null || sid.isBlank()) {
            return Optional.empty();
        }
        Optional<String> raw = repository.get(sid);
        if (raw.isEmpty()) {
            return Optional.empty();
        }
        IamSession session = read(raw.get());
        Instant now = clock.instant();
        if (IamSession.STATUS_REVOKED.equals(session.status())) {
            throw new IamException(IamErrorCode.SESSION_REVOKED, "SSO session revoked");
        }
        if (session.expiresAt() != null && !session.expiresAt().isAfter(now)) {
            repository.delete(sid);
            throw new IamException(IamErrorCode.SESSION_EXPIRED, "SSO session expired");
        }
        return Optional.of(session);
    }

    @Override
    public Optional<IamSession> inspect(String sid) {
        if (sid == null || sid.isBlank()) {
            return Optional.empty();
        }
        return repository.get(sid).map(this::read);
    }

    @Override
    public List<IamSession> listBySubject(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            return List.of();
        }
        List<IamSession> sessions = new ArrayList<>();
        for (String sid : repository.listSidsBySubject(subjectId)) {
            inspect(sid).ifPresent(sessions::add);
        }
        return sessions;
    }

    @Override
    public IamSession touch(String sid) {
        IamSession session = require(sid);
        IamSession updated = session.withLastAccessAt(clock.instant());
        Duration remaining = repository.getTtl(sid);
        if (remaining == null || remaining.isZero() || remaining.isNegative()) {
            remaining = Duration.between(clock.instant(), updated.expiresAt());
        }
        if (remaining.isZero() || remaining.isNegative()) {
            throw new IamException(IamErrorCode.SESSION_EXPIRED, "SSO session expired");
        }
        repository.save(sid, write(updated), remaining);
        return updated;
    }

    @Override
    public void revoke(String sid) {
        IamSession session = repository.get(sid)
                .map(this::read)
                .orElseThrow(() -> new IamException(IamErrorCode.SESSION_NOT_FOUND, "SSO session not found"));
        Duration remaining = repository.getTtl(sid);
        if (remaining == null || remaining.isZero() || remaining.isNegative()) {
            remaining = Duration.ofSeconds(1);
        }
        repository.save(sid, write(session.withStatus(IamSession.STATUS_REVOKED)), remaining);
    }

    @Override
    public void revokeAllForSubject(String subjectId) {
        for (String sid : repository.listSidsBySubject(subjectId)) {
            try {
                revoke(sid);
            } catch (IamException ex) {
                if (ex.getErrorCode() != IamErrorCode.SESSION_NOT_FOUND) {
                    throw ex;
                }
            }
        }
    }

    @Override
    public void expire(String sid) {
        IamSession session = repository.get(sid)
                .map(this::read)
                .orElseThrow(() -> new IamException(IamErrorCode.SESSION_NOT_FOUND, "SSO session not found"));
        Duration remaining = repository.getTtl(sid);
        if (remaining == null || remaining.isZero() || remaining.isNegative()) {
            remaining = Duration.ofMinutes(1);
        }
        repository.save(sid, write(session.withExpiresAt(clock.instant().minusSeconds(1))), remaining);
    }

    @Override
    public void delete(String sid) {
        if (sid != null && !sid.isBlank()) {
            repository.get(sid).map(this::read).ifPresent(session -> repository.removeSubjectIndex(session.subjectId(), sid));
            repository.delete(sid);
        }
    }

    @Override
    public Duration ttl() {
        return properties.getSessionTtl();
    }

    @Override
    public SessionCount countActive() {
        Optional<String> cached = repository.getRaw(RedisKeyConstants.ADMIN_SESSION_COUNT_CACHE);
        if (cached.isPresent()) {
            return parseCached(cached.get());
        }
        int scanCap = 10_000;
        int inspectCap = 500;
        List<String> sids = repository.scanSessionSids(scanCap);
        boolean approximate = sids.size() >= scanCap;
        long active;
        if (sids.size() <= inspectCap) {
            Instant now = clock.instant();
            active = 0;
            for (String sid : sids) {
                Optional<IamSession> session = inspect(sid);
                if (session.isEmpty()) {
                    continue;
                }
                IamSession value = session.get();
                if (!IamSession.STATUS_ACTIVE.equals(value.status())) {
                    continue;
                }
                if (value.expiresAt() != null && !value.expiresAt().isAfter(now)) {
                    continue;
                }
                active++;
            }
        } else {
            active = sids.size();
            approximate = true;
        }
        repository.saveRaw(
                RedisKeyConstants.ADMIN_SESSION_COUNT_CACHE, active + "|" + approximate, Duration.ofSeconds(30));
        return new SessionCount(active, approximate, false);
    }

    private static SessionCount parseCached(String raw) {
        String[] parts = raw.split("\\|", 2);
        long active = Long.parseLong(parts[0]);
        boolean approximate = parts.length > 1 && Boolean.parseBoolean(parts[1]);
        return new SessionCount(active, approximate, true);
    }

    private String write(IamSession session) {
        try {
            return objectMapper.writeValueAsString(session);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "failed to serialize SSO session", ex);
        }
    }

    private IamSession read(String json) {
        try {
            return objectMapper.readValue(json, IamSession.class);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INVALID_SSO_COOKIE, "SSO session payload is corrupt");
        }
    }

    private static String randomSid() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
