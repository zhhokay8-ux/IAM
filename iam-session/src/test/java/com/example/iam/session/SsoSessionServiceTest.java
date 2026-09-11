package com.example.iam.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.session.repository.IamSessionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SsoSessionServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T05:00:00Z");

    @Mock
    private IamSessionRepository repository;

    private ObjectMapper objectMapper;
    private IamSessionServiceImpl service;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        IamRedisProperties properties = new IamRedisProperties();
        properties.setSessionTtl(Duration.ofHours(8));
        service = new IamSessionServiceImpl(repository, properties, objectMapper, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void createStoresJsonPayloadWithEightHourTtl() throws Exception {
        IamSession created = service.create("sub-1", "portal", "pwd");
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(repository).save(eq(created.sid()), json.capture(), eq(Duration.ofHours(8)));
        IamSession stored = objectMapper.readValue(json.getValue(), IamSession.class);
        assertEquals("sub-1", stored.subjectId());
        assertEquals("portal", stored.clientId());
        assertEquals("pwd", stored.authenticationLevel());
        assertEquals(IamSession.STATUS_ACTIVE, stored.status());
        assertEquals(NOW, stored.createdAt());
        assertEquals(NOW, stored.lastAccessAt());
        assertEquals(NOW.plus(Duration.ofHours(8)), stored.expiresAt());
        assertTrue(created.sid().length() >= 32);
    }

    @Test
    void requireReturnsActiveSession() throws Exception {
        IamSession session = sample("ACTIVE", NOW.plusSeconds(60));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        IamSession loaded = service.require(session.sid());
        assertEquals("sub-1", loaded.subjectId());
    }

    @Test
    void missingSessionThrowsNotFound() {
        when(repository.get("missing")).thenReturn(Optional.empty());
        IamException ex = assertThrows(IamException.class, () -> service.require("missing"));
        assertEquals(IamErrorCode.SESSION_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void expiredSessionThrowsExpiredAndDeletes() throws Exception {
        IamSession session = sample("ACTIVE", NOW.minusSeconds(1));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        IamException ex = assertThrows(IamException.class, () -> service.require(session.sid()));
        assertEquals(IamErrorCode.SESSION_EXPIRED, ex.getErrorCode());
        verify(repository).delete(session.sid());
    }

    @Test
    void revokedSessionThrowsRevoked() throws Exception {
        IamSession session = sample("REVOKED", NOW.plusSeconds(60));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        IamException ex = assertThrows(IamException.class, () -> service.require(session.sid()));
        assertEquals(IamErrorCode.SESSION_REVOKED, ex.getErrorCode());
    }

    @Test
    void corruptPayloadThrowsInvalidCookie() {
        when(repository.get("sid")).thenReturn(Optional.of("{not-json"));
        IamException ex = assertThrows(IamException.class, () -> service.require("sid"));
        assertEquals(IamErrorCode.INVALID_SSO_COOKIE, ex.getErrorCode());
    }

    @Test
    void touchUpdatesLastAccessWithoutResettingTtl() throws Exception {
        IamSession session = sample("ACTIVE", NOW.plus(Duration.ofHours(8)));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        when(repository.getTtl(session.sid())).thenReturn(Duration.ofHours(7));
        service.touch(session.sid());
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(repository).save(eq(session.sid()), json.capture(), eq(Duration.ofHours(7)));
        IamSession updated = objectMapper.readValue(json.getValue(), IamSession.class);
        assertEquals(NOW, updated.lastAccessAt());
    }

    @Test
    void revokePersistsRevokedStatus() throws Exception {
        IamSession session = sample("ACTIVE", NOW.plusSeconds(60));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        when(repository.getTtl(session.sid())).thenReturn(Duration.ofHours(1));
        service.revoke(session.sid());
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(repository).save(eq(session.sid()), json.capture(), any());
        assertEquals(IamSession.STATUS_REVOKED, objectMapper.readValue(json.getValue(), IamSession.class).status());
    }

    @Test
    void inspectReturnsRevokedWithoutThrowing() throws Exception {
        IamSession session = sample("REVOKED", NOW.plusSeconds(60));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        assertEquals(IamSession.STATUS_REVOKED, service.inspect(session.sid()).orElseThrow().status());
    }

    @Test
    void listBySubjectLoadsIndexedSidsAndSkipsMissing() throws Exception {
        IamSession session = sample("ACTIVE", NOW.plusSeconds(60));
        when(repository.listSidsBySubject("sub-1")).thenReturn(java.util.Set.of(session.sid(), "gone"));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        when(repository.get("gone")).thenReturn(Optional.empty());
        java.util.List<IamSession> listed = service.listBySubject("sub-1");
        assertEquals(1, listed.size());
        assertEquals(session.sid(), listed.get(0).sid());
    }

    @Test
    void expireRewritesExpiresAtInThePast() throws Exception {
        IamSession session = sample("ACTIVE", NOW.plusSeconds(60));
        when(repository.get(session.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(session)));
        when(repository.getTtl(session.sid())).thenReturn(Duration.ofMinutes(5));
        service.expire(session.sid());
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(repository).save(eq(session.sid()), json.capture(), eq(Duration.ofMinutes(5)));
        assertEquals(NOW.minusSeconds(1), objectMapper.readValue(json.getValue(), IamSession.class).expiresAt());
    }

    @Test
    void countActiveInspectsPayloadsAndCachesResult() throws Exception {
        IamSession active = sample("ACTIVE", NOW.plusSeconds(60));
        IamSession revoked = new IamSession(
                "sid-2", "sub-1", NOW, NOW, NOW.plusSeconds(60), "pwd", "portal", IamSession.STATUS_REVOKED);
        when(repository.getRaw("admin:cache:session-count")).thenReturn(Optional.empty());
        when(repository.scanSessionSids(10_000)).thenReturn(java.util.List.of(active.sid(), revoked.sid()));
        when(repository.get(active.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(active)));
        when(repository.get(revoked.sid())).thenReturn(Optional.of(objectMapper.writeValueAsString(revoked)));
        SessionCount count = service.countActive();
        assertEquals(1, count.active());
        assertEquals(false, count.approximate());
        assertEquals(false, count.fromCache());
        verify(repository).saveRaw(eq("admin:cache:session-count"), eq("1|false"), eq(Duration.ofSeconds(30)));
    }

    @Test
    void countActiveUsesShortTtlCache() {
        when(repository.getRaw("admin:cache:session-count")).thenReturn(Optional.of("42|true"));
        SessionCount count = service.countActive();
        assertEquals(42, count.active());
        assertEquals(true, count.approximate());
        assertEquals(true, count.fromCache());
    }

    private static IamSession sample(String status, Instant expiresAt) {
        return new IamSession("sid-1", "sub-1", NOW.minusSeconds(10), NOW.minusSeconds(5), expiresAt, "pwd", "portal", status);
    }
}
