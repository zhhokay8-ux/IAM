package com.example.iam.embed;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSessionService;
import java.time.Clock;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EmbedCodeValidator {

    private final OriginValidator originValidator;
    private final IamSessionService sessionService;
    private final Clock clock;

    @Autowired
    public EmbedCodeValidator(OriginValidator originValidator, IamSessionService sessionService) {
        this(originValidator, sessionService, Clock.systemUTC());
    }

    EmbedCodeValidator(OriginValidator originValidator, IamSessionService sessionService, Clock clock) {
        this.originValidator = originValidator;
        this.sessionService = sessionService;
        this.clock = clock;
    }

    public EmbedContext validateForExchange(EmbedContext stored, ExchangeEmbedCodeRequest request, String childClientId) {
        if (stored == null) {
            throw new IamException(IamErrorCode.EMBED_CODE_NOT_FOUND, "embed code not found");
        }
        if (stored.expiresAt() == null || !stored.expiresAt().isAfter(clock.instant())) {
            throw new IamException(IamErrorCode.EMBED_CODE_EXPIRED, "embed code expired");
        }
        if (!stored.childClientId().equals(childClientId)) {
            throw new IamException(IamErrorCode.EMBED_CLIENT_MISMATCH, "embed code is bound to another child client");
        }
        originValidator.requireMatch(request.origin(), stored.origin());
        if (request.nonce() == null || request.nonce().isBlank() || !request.nonce().equals(stored.nonce())) {
            throw new IamException(IamErrorCode.EMBED_NONCE_MISMATCH, "embed nonce mismatch");
        }
        if (request.sessionId() != null
                && !request.sessionId().isBlank()
                && !request.sessionId().equals(stored.sessionId())) {
            throw new IamException(IamErrorCode.EMBED_SESSION_MISMATCH, "embed session mismatch");
        }
        try {
            sessionService.require(stored.sessionId());
        } catch (IamException ex) {
            throw new IamException(IamErrorCode.EMBED_SESSION_MISMATCH, "embed session is invalid", ex);
        }
        return stored;
    }

    Instant now() {
        return clock.instant();
    }
}
