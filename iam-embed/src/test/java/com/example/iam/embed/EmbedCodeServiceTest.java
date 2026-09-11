package com.example.iam.embed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import com.example.iam.embed.repository.EmbedCodeRepository;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.service.IamUserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EmbedCodeServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T05:00:00Z");
    private static final String PARENT = "portal";
    private static final String CHILD = "system-n";
    private static final String ORIGIN = "https://portal.example.com";
    private static final String PATH = "/orders/1";
    private static final String NONCE = "nonce-1";
    private static final String SID = "sid-1";
    private static final UUID SUBJECT = UUID.fromString("01999a2e-7c3a-7000-8000-000000000001");

    @Mock
    private EmbedPolicyService policyService;

    @Mock
    private EmbedCodeGenerator generator;

    @Mock
    private EmbedCodeRepository repository;

    @Mock
    private IamUserService userService;

    @Mock
    private IamSessionService sessionService;

    private ObjectMapper objectMapper;
    private EmbedCodeServiceImpl service;
    private EmbedCodeValidator validator;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        OriginValidator originValidator = new OriginValidator(new IamOriginValidator());
        validator = new EmbedCodeValidator(originValidator, sessionService, Clock.fixed(NOW, ZoneOffset.UTC));
        IamRedisProperties properties = new IamRedisProperties();
        properties.setEmbedCodeTtl(Duration.ofSeconds(30));
        service = new EmbedCodeServiceImpl(
                policyService,
                originValidator,
                generator,
                validator,
                repository,
                userService,
                properties,
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void validIssueAndExchange() throws Exception {
        when(userService.requireUser(SUBJECT)).thenReturn(new IamUserEntity());
        when(policyService.requireActive(PARENT, CHILD, ORIGIN, PATH)).thenReturn(policy());
        when(generator.next()).thenReturn("EC_valid");
        CreateEmbedCodeResponse issued = service.issue(createRequest(), PARENT, SUBJECT.toString(), SID);
        assertEquals("EC_valid", issued.code());
        assertEquals(NOW.plusSeconds(30), issued.expiresAt());
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(repository).save(eq("EC_valid"), json.capture(), eq(Duration.ofSeconds(30)));
        when(repository.get("EC_valid")).thenReturn(Optional.of(json.getValue()));
        when(repository.consume("EC_valid")).thenReturn(Optional.of(json.getValue()));
        when(sessionService.require(SID)).thenReturn(session());
        EmbedContext exchanged = service.exchange(exchangeRequest("EC_valid", ORIGIN, NONCE, SID), CHILD);
        assertEquals(SUBJECT.toString(), exchanged.subjectId());
        assertEquals(PARENT, exchanged.parentClientId());
        assertEquals(CHILD, exchanged.childClientId());
    }

    @Test
    void expired() throws Exception {
        EmbedContext stored = context(NOW.minusSeconds(1));
        when(repository.get("EC_exp")).thenReturn(Optional.of(objectMapper.writeValueAsString(stored)));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(exchangeRequest("EC_exp", ORIGIN, NONCE, SID), CHILD));
        assertEquals(IamErrorCode.EMBED_CODE_EXPIRED, ex.getErrorCode());
        verify(repository, never()).consume(any());
    }

    @Test
    void replay() {
        when(repository.get("EC_replay")).thenReturn(Optional.empty());
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(exchangeRequest("EC_replay", ORIGIN, NONCE, SID), CHILD));
        assertEquals(IamErrorCode.EMBED_CODE_REPLAY, ex.getErrorCode());
    }

    @Test
    void wrongParent() {
        when(userService.requireUser(SUBJECT)).thenReturn(new IamUserEntity());
        when(policyService.requireActive("other-parent", CHILD, ORIGIN, PATH))
                .thenThrow(new IamException(IamErrorCode.FORBIDDEN, "no policy"));
        IamException ex = assertThrows(
                IamException.class, () -> service.issue(createRequest(), "other-parent", SUBJECT.toString(), SID));
        assertEquals(IamErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(repository, never()).save(any(), any(), any());
    }

    @Test
    void wrongChild() throws Exception {
        EmbedContext stored = context(NOW.plusSeconds(30));
        when(repository.get(stored.code())).thenReturn(Optional.of(objectMapper.writeValueAsString(stored)));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(exchangeRequest(stored.code(), ORIGIN, NONCE, SID), "other-child"));
        assertEquals(IamErrorCode.EMBED_CLIENT_MISMATCH, ex.getErrorCode());
        verify(repository, never()).consume(any());
    }

    @Test
    void wrongOrigin() throws Exception {
        EmbedContext stored = context(NOW.plusSeconds(30));
        when(repository.get(stored.code())).thenReturn(Optional.of(objectMapper.writeValueAsString(stored)));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(exchangeRequest(stored.code(), "https://evil.example.com", NONCE, SID), CHILD));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
        verify(repository, never()).consume(any());
    }

    @Test
    void wrongPath() {
        when(userService.requireUser(SUBJECT)).thenReturn(new IamUserEntity());
        when(policyService.requireActive(PARENT, CHILD, ORIGIN, "/admin"))
                .thenThrow(new IamException(IamErrorCode.EMBED_PATH_NOT_ALLOWED, "path"));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.issue(
                        new CreateEmbedCodeRequest(CHILD, "/admin", ORIGIN, NONCE),
                        PARENT,
                        SUBJECT.toString(),
                        SID));
        assertEquals(IamErrorCode.EMBED_PATH_NOT_ALLOWED, ex.getErrorCode());
    }

    @Test
    void wrongNonce() throws Exception {
        EmbedContext stored = context(NOW.plusSeconds(30));
        when(repository.get(stored.code())).thenReturn(Optional.of(objectMapper.writeValueAsString(stored)));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(exchangeRequest(stored.code(), ORIGIN, "other-nonce", SID), CHILD));
        assertEquals(IamErrorCode.EMBED_NONCE_MISMATCH, ex.getErrorCode());
        verify(repository, never()).consume(any());
    }

    @Test
    void wrongSession() throws Exception {
        EmbedContext stored = context(NOW.plusSeconds(30));
        when(repository.get(stored.code())).thenReturn(Optional.of(objectMapper.writeValueAsString(stored)));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(exchangeRequest(stored.code(), ORIGIN, NONCE, "other-sid"), CHILD));
        assertEquals(IamErrorCode.EMBED_SESSION_MISMATCH, ex.getErrorCode());
        verify(repository, never()).consume(any());
    }

    @Test
    void policyDisabled() {
        when(userService.requireUser(SUBJECT)).thenReturn(new IamUserEntity());
        when(policyService.requireActive(PARENT, CHILD, ORIGIN, PATH))
                .thenThrow(new IamException(IamErrorCode.EMBED_POLICY_DISABLED, "disabled"));
        IamException ex = assertThrows(
                IamException.class, () -> service.issue(createRequest(), PARENT, SUBJECT.toString(), SID));
        assertEquals(IamErrorCode.EMBED_POLICY_DISABLED, ex.getErrorCode());
    }

    @Test
    void issuedCodeIsShortLived() {
        when(userService.requireUser(SUBJECT)).thenReturn(new IamUserEntity());
        when(policyService.requireActive(PARENT, CHILD, ORIGIN, PATH)).thenReturn(policy());
        when(generator.next()).thenReturn("EC_ttl");
        CreateEmbedCodeResponse issued = service.issue(createRequest(), PARENT, SUBJECT.toString(), SID);
        assertTrue(Duration.between(NOW, issued.expiresAt()).equals(Duration.ofSeconds(30)));
    }

    private static CreateEmbedCodeRequest createRequest() {
        return new CreateEmbedCodeRequest(CHILD, PATH, ORIGIN, NONCE);
    }

    private static ExchangeEmbedCodeRequest exchangeRequest(String code, String origin, String nonce, String sessionId) {
        return new ExchangeEmbedCodeRequest(code, origin, nonce, sessionId);
    }

    private static EmbedContext context(Instant expiresAt) {
        return new EmbedContext("EC_stored", PARENT, CHILD, SUBJECT.toString(), SID, NONCE, ORIGIN, "/orders/*", NOW, expiresAt);
    }

    private static IamEmbedPolicyEntity policy() {
        return IamEmbedPolicyEntity.builder()
                .allowedPath("/orders/*")
                .parentOrigin(ORIGIN)
                .status("ACTIVE")
                .build();
    }

    private static IamSession session() {
        return new IamSession(SID, SUBJECT.toString(), NOW, NOW, NOW.plusSeconds(3600), "pwd", PARENT, "ACTIVE");
    }
}
