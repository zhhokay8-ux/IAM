package com.example.iam.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.migration.repository.MigrationTicketRepository;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MigrationTicketServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T07:00:00Z");
    private static final String CLIENT = "portal";
    private static final String RETURN_TO = "https://portal.example.com/login/callback";
    private static final String SUBJECT = "01999a2e-7c3a-7000-8000-000000000086";
    private static final String BROWSER = "browser-binding";
    private static final String NONCE = "nonce-1";

    @Mock
    private MigrationTicketRepository repository;

    @Mock
    private IamClientService clientService;

    @Mock
    private IdentityMappingResolver mappingResolver;

    @Mock
    private MigrationAuditService auditService;

    private MigrationProperties properties;
    private ObjectMapper objectMapper;
    private MigrationTicketServiceImpl service;

    @BeforeEach
    void setUp() {
        properties = new MigrationProperties();
        objectMapper = new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        service = new MigrationTicketServiceImpl(
                repository,
                properties,
                clientService,
                mappingResolver,
                new IamRedirectUriValidator(),
                auditService,
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void issuesOneTimeTicketBoundToClientUserBrowserAndNonce() {
        stubIssue();
        CreateMigrationTicketResponse response = service.issue(issueRequest());
        assertEquals(NOW.plusSeconds(45), response.expiresAt());
        verify(repository).save(eq(response.ticket()), any(), eq(Duration.ofSeconds(45)));
        MigrationTicket stored = redeemOk(response.ticket());
        assertEquals(CLIENT, stored.clientId());
        assertEquals(SUBJECT, stored.subjectId());
        assertEquals(BROWSER, stored.browserSession());
        assertEquals(NONCE, stored.nonce());
    }

    @Test
    void ticketReplayIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        redeemOk(ticket);
        when(repository.get(ticket)).thenReturn(Optional.empty());
        IamException ex = assertThrows(IamException.class, () -> redeem(ticket, CLIENT, SUBJECT, BROWSER, NONCE));
        assertEquals(IamErrorCode.MIGRATION_TICKET_REPLAY, ex.getErrorCode());
    }

    @Test
    void ticketExpiredIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        service = new MigrationTicketServiceImpl(
                repository,
                properties,
                clientService,
                mappingResolver,
                new IamRedirectUriValidator(),
                auditService,
                objectMapper,
                Clock.fixed(NOW.plusSeconds(90), ZoneOffset.UTC));
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        IamException ex = assertThrows(IamException.class, () -> redeem(ticket, CLIENT, SUBJECT, BROWSER, NONCE));
        assertEquals(IamErrorCode.MIGRATION_TICKET_EXPIRED, ex.getErrorCode());
        verify(repository).consume(ticket);
    }

    @Test
    void wrongClientIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        IamException ex = assertThrows(IamException.class, () -> redeem(ticket, "other", SUBJECT, BROWSER, NONCE));
        assertEquals(IamErrorCode.MIGRATION_CLIENT_MISMATCH, ex.getErrorCode());
    }

    @Test
    void wrongUserIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        IamException ex = assertThrows(
                IamException.class, () -> redeem(ticket, CLIENT, "01999a2e-7c3a-7000-8000-000000000099", BROWSER, NONCE));
        assertEquals(IamErrorCode.MIGRATION_USER_MISMATCH, ex.getErrorCode());
    }

    @Test
    void wrongBrowserSessionIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        IamException ex = assertThrows(IamException.class, () -> redeem(ticket, CLIENT, SUBJECT, "other-browser", NONCE));
        assertEquals(IamErrorCode.MIGRATION_BROWSER_MISMATCH, ex.getErrorCode());
    }

    @Test
    void wrongNonceIsRejected() {
        stubIssue();
        String ticket = service.issue(issueRequest()).ticket();
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        IamException ex = assertThrows(IamException.class, () -> redeem(ticket, CLIENT, SUBJECT, BROWSER, "other-nonce"));
        assertEquals(IamErrorCode.MIGRATION_NONCE_MISMATCH, ex.getErrorCode());
    }

    @Test
    void mappingMissingIsRejected() {
        when(clientService.requireActiveClient(CLIENT)).thenReturn(new IamClientEntity());
        when(mappingResolver.resolve("portal", "zhangsan", null))
                .thenThrow(new IamException(IamErrorCode.MAPPING_NOT_FOUND, "missing"));
        IamException ex = assertThrows(IamException.class, () -> service.issue(issueRequest()));
        assertEquals(IamErrorCode.MAPPING_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void iamDisabledRejectsTicketIssue() {
        properties.setEnabled(false);
        IamException ex = assertThrows(IamException.class, () -> service.issue(issueRequest()));
        assertEquals(IamErrorCode.MIGRATION_DISABLED, ex.getErrorCode());
    }

    @Test
    void rollbackLegacyModeRejectsIamTicket() {
        properties.getMigration().setMode("legacy");
        IamException ex = assertThrows(IamException.class, () -> service.issue(issueRequest()));
        assertEquals(IamErrorCode.MIGRATION_DISABLED, ex.getErrorCode());
    }

    @Test
    void dualModeAllowsTicketIssue() {
        properties.getMigration().setMode("dual");
        stubIssue();
        CreateMigrationTicketResponse response = service.issue(issueRequest());
        assertEquals("/migration/login?ticket=" + response.ticket(), response.loginPath());
    }

    @Test
    void jwtMustNotBeUsedAsTicket() {
        IamException ex = assertThrows(
                IamException.class,
                () -> redeem("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1LTEwMDA4NiJ9.signaturevalue", CLIENT, SUBJECT, BROWSER, NONCE));
        assertEquals(IamErrorCode.MIGRATION_LEGACY_IN_URL, ex.getErrorCode());
    }

    private void stubIssue() {
        when(clientService.requireActiveClient(CLIENT)).thenReturn(new IamClientEntity());
        when(clientService.get(CLIENT))
                .thenReturn(new ClientResponse(
                        UUID.randomUUID(),
                        CLIENT,
                        "Portal",
                        "confidential",
                        "ACTIVE",
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(new RedirectUriInput(RETURN_TO, "LOGIN_CALLBACK")),
                        NOW,
                        NOW));
        when(mappingResolver.resolve("portal", "zhangsan", null))
                .thenReturn(new IdentityMappingResponse(
                        UUID.randomUUID(), SUBJECT, "portal", "zhangsan", "zhangsan", "ACTIVE", NOW));
    }

    private MigrationTicket redeemOk(String ticket) {
        when(repository.get(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        when(repository.consume(ticket)).thenReturn(Optional.of(storedJson(ticket)));
        return redeem(ticket, CLIENT, SUBJECT, BROWSER, NONCE);
    }

    private MigrationTicket redeem(String ticket, String clientId, String subject, String browser, String nonce) {
        return service.redeem(new RedeemMigrationTicketRequest(ticket, clientId, subject, browser, nonce));
    }

    private String storedJson(String ticket) {
        try {
            return objectMapper.writeValueAsString(new MigrationTicket(
                    ticket, CLIENT, SUBJECT, BROWSER, NONCE, RETURN_TO, NOW, NOW.plusSeconds(45)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static CreateMigrationTicketRequest issueRequest() {
        return new CreateMigrationTicketRequest(
                CLIENT, "secret", "portal", "zhangsan", null, BROWSER, NONCE, RETURN_TO);
    }
}
