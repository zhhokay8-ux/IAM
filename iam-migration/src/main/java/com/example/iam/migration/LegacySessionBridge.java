package com.example.iam.migration;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class LegacySessionBridge {

    private final LegacySessionValidator sessionValidator;
    private final MigrationTicketService ticketService;
    private final MigrationProperties properties;

    public LegacySessionBridge(
            LegacySessionValidator sessionValidator,
            MigrationTicketService ticketService,
            MigrationProperties properties) {
        this.sessionValidator = sessionValidator;
        this.ticketService = ticketService;
        this.properties = properties;
    }

    public CreateMigrationTicketResponse start(
            String legacySessionCookie, String clientId, String nonce, String returnTo) {
        properties.requireIamLoginEnabled();
        if (!StringUtils.hasText(legacySessionCookie)) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "legacy session is required");
        }
        MigrationTicketServiceImpl.rejectLegacyInUrl(legacySessionCookie);
        LegacyPrincipal principal = sessionValidator.requireValid(legacySessionCookie);
        String browserSession = CurrentUserResolver.browserBinding(legacySessionCookie);
        return ticketService.issue(new CreateMigrationTicketRequest(
                clientId,
                null,
                principal.systemCode(),
                principal.externalUserId(),
                null,
                browserSession,
                nonce,
                returnTo));
    }
}
