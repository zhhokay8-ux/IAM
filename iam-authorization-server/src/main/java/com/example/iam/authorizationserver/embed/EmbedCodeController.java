package com.example.iam.authorizationserver.embed;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.token.ClientAuthenticationProvider;
import com.example.iam.authorizationserver.oauth.token.TokenRequest;
import com.example.iam.authorizationserver.sso.SsoAuthenticationService;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.embed.CreateEmbedCodeRequest;
import com.example.iam.embed.CreateEmbedCodeResponse;
import com.example.iam.embed.EmbedCodeService;
import com.example.iam.embed.EmbedContext;
import com.example.iam.embed.ExchangeEmbedCodeRequest;
import com.example.iam.session.IamSession;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EmbedCodeController {

    private final EmbedCodeService embedCodeService;
    private final SsoAuthenticationService ssoAuthenticationService;
    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final IamAuditService auditService;

    public EmbedCodeController(
            EmbedCodeService embedCodeService,
            SsoAuthenticationService ssoAuthenticationService,
            ClientAuthenticationProvider clientAuthenticationProvider,
            IamAuditService auditService) {
        this.embedCodeService = embedCodeService;
        this.ssoAuthenticationService = ssoAuthenticationService;
        this.clientAuthenticationProvider = clientAuthenticationProvider;
        this.auditService = auditService;
    }

    @PostMapping(path = "/api/embed/code", consumes = MediaType.APPLICATION_JSON_VALUE)
    public CreateEmbedCodeResponse issue(@RequestBody CreateEmbedCodeRequest request, HttpServletRequest httpRequest) {
        IamSession session = ssoAuthenticationService.requireCurrent(httpRequest);
        CreateEmbedCodeResponse response =
                embedCodeService.issue(request, session.clientId(), session.subjectId(), session.sid());
        auditService.success(AuditEvent.EMBED_CODE_CREATED, session.subjectId(), session.clientId(), null);
        return response;
    }

    @PostMapping(path = "/api/embed/exchange", consumes = MediaType.APPLICATION_JSON_VALUE)
    public EmbedContext exchange(@RequestBody ExchangeEmbedCodeRequest request, HttpServletRequest httpRequest) {
        IamClientEntity child = clientAuthenticationProvider.authenticate(
                httpRequest, new TokenRequest(null, null, null, null, null, null, null, null, null));
        ClientAuthenticationProvider.requireConfidential(child);
        EmbedContext context = embedCodeService.exchange(request, child.getClientId());
        auditService.success(AuditEvent.EMBED_CODE_EXCHANGED, context.subjectId(), child.getClientId(), null);
        return context;
    }
}
