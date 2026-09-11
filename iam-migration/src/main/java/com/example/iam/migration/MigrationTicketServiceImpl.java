package com.example.iam.migration;

import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.migration.repository.MigrationTicketRepository;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class MigrationTicketServiceImpl implements MigrationTicketService {

    public static final String LOGIN_PATH = "/migration/login";

    private final MigrationTicketRepository repository;
    private final MigrationProperties properties;
    private final IamClientService clientService;
    private final IdentityMappingResolver mappingResolver;
    private final IamRedirectUriValidator redirectUriValidator;
    private final MigrationAuditService auditService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public MigrationTicketServiceImpl(
            MigrationTicketRepository repository,
            MigrationProperties properties,
            IamClientService clientService,
            IdentityMappingResolver mappingResolver,
            IamRedirectUriValidator redirectUriValidator,
            MigrationAuditService auditService,
            ObjectMapper objectMapper) {
        this(
                repository,
                properties,
                clientService,
                mappingResolver,
                redirectUriValidator,
                auditService,
                objectMapper,
                Clock.systemUTC());
    }

    MigrationTicketServiceImpl(
            MigrationTicketRepository repository,
            MigrationProperties properties,
            IamClientService clientService,
            IdentityMappingResolver mappingResolver,
            IamRedirectUriValidator redirectUriValidator,
            MigrationAuditService auditService,
            ObjectMapper objectMapper,
            Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clientService = clientService;
        this.mappingResolver = mappingResolver;
        this.redirectUriValidator = redirectUriValidator;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public CreateMigrationTicketResponse issue(CreateMigrationTicketRequest request) {
        properties.requireIamLoginEnabled();
        if (request == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "migration ticket request is required");
        }
        rejectLegacyInUrl(request.browserSession());
        rejectLegacyInUrl(request.nonce());
        clientService.requireActiveClient(request.clientId());
        IdentityMappingResponse mapping =
                mappingResolver.resolve(request.systemCode(), request.externalUserId(), request.subjectId());
        String browserSession = requireOpaqueBinding(request.browserSession(), "browser_session");
        String nonce = requireOpaqueBinding(request.nonce(), "nonce");
        String returnTo = requireText(request.returnTo(), "return_to");
        List<String> registered = clientService.get(request.clientId()).redirectUris().stream()
                .map(RedirectUriInput::redirectUri)
                .toList();
        redirectUriValidator.validateRedirectUri(returnTo, registered);

        Instant now = clock.instant();
        Duration ttl = properties.ticketTtl();
        String ticketId = IdGenerator.next();
        MigrationTicket ticket = new MigrationTicket(
                ticketId,
                request.clientId(),
                mapping.subjectId(),
                browserSession,
                nonce,
                returnTo,
                now,
                now.plus(ttl));
        repository.save(ticketId, write(ticket), ttl);
        auditService.record("MIGRATION_SUCCESS", mapping.subjectId(), request.clientId(), "SUCCESS", null);
        return new CreateMigrationTicketResponse(ticketId, ticket.expiresAt(), LOGIN_PATH + "?ticket=" + ticketId);
    }

    @Override
    public MigrationTicket redeem(RedeemMigrationTicketRequest request) {
        properties.requireIamLoginEnabled();
        if (request == null || !StringUtils.hasText(request.ticket())) {
            throw new IamException(IamErrorCode.MIGRATION_TICKET_NOT_FOUND, "ticket is required");
        }
        rejectLegacyInUrl(request.ticket());
        String raw = repository
                .get(request.ticket())
                .orElseThrow(() -> new IamException(
                        IamErrorCode.MIGRATION_TICKET_REPLAY, "migration ticket not found or already used"));
        MigrationTicket stored = read(raw);
        Instant now = clock.instant();
        if (stored.expiresAt() == null || !now.isBefore(stored.expiresAt())) {
            repository.consume(request.ticket());
            auditService.record("MIGRATION_FAILURE", stored.subjectId(), stored.clientId(), "FAILURE", "expired");
            throw new IamException(IamErrorCode.MIGRATION_TICKET_EXPIRED, "migration ticket expired");
        }
        if (StringUtils.hasText(request.clientId()) && !stored.clientId().equals(request.clientId())) {
            throw new IamException(IamErrorCode.MIGRATION_CLIENT_MISMATCH, "client_id does not match ticket");
        }
        if (StringUtils.hasText(request.subjectId()) && !stored.subjectId().equals(request.subjectId())) {
            throw new IamException(IamErrorCode.MIGRATION_USER_MISMATCH, "subject does not match ticket");
        }
        if (!HashUtils.constantTimeEquals(stored.browserSession(), request.browserSession())) {
            throw new IamException(IamErrorCode.MIGRATION_BROWSER_MISMATCH, "browser/session binding mismatch");
        }
        if (!HashUtils.constantTimeEquals(stored.nonce(), request.nonce())) {
            throw new IamException(IamErrorCode.MIGRATION_NONCE_MISMATCH, "nonce mismatch");
        }
        if (repository.consume(request.ticket()).isEmpty()) {
            throw new IamException(IamErrorCode.MIGRATION_TICKET_REPLAY, "migration ticket already used");
        }
        auditService.record("MIGRATION_SUCCESS", stored.subjectId(), stored.clientId(), "SUCCESS", null);
        return stored;
    }

    static void rejectLegacyInUrl(String value) {
        if (value == null) {
            return;
        }
        if (looksLikeJwt(value) || value.toLowerCase().contains("legacy-session")) {
            throw new IamException(
                    IamErrorCode.MIGRATION_LEGACY_IN_URL, "legacy session or JWT must not be placed in the URL");
        }
    }

    private static boolean looksLikeJwt(String value) {
        String[] parts = value.split("\\.");
        return parts.length == 3 && parts[0].length() > 8 && parts[1].length() > 8;
    }

    private static String requireOpaqueBinding(String value, String field) {
        String text = requireText(value, field);
        rejectLegacyInUrl(text);
        return text;
    }

    private static String requireText(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, field + " is required");
        }
        return value.trim();
    }

    private String write(MigrationTicket ticket) {
        try {
            return objectMapper.writeValueAsString(ticket);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "failed to serialize migration ticket", ex);
        }
    }

    private MigrationTicket read(String raw) {
        try {
            return objectMapper.readValue(raw, MigrationTicket.class);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.MIGRATION_TICKET_NOT_FOUND, "migration ticket is invalid", ex);
        }
    }
}
