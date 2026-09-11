package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class TokenServiceImpl implements TokenService {

    private final List<TokenGrantHandler> handlers;
    private final IamAuditService auditService;

    public TokenServiceImpl(List<TokenGrantHandler> handlers, IamAuditService auditService) {
        this.handlers = handlers;
        this.auditService = auditService;
    }

    @Override
    public TokenResponse issue(TokenRequest request, IamClientEntity client) {
        if (request == null || request.grantType() == null || request.grantType().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "grant_type is required");
        }
        TokenResponse response = handlers.stream()
                .filter(handler -> handler.supports(request.grantType()))
                .findFirst()
                .orElseThrow(() -> new IamException(
                        IamErrorCode.INVALID_GRANT_TYPE, "unsupported grant_type: " + request.grantType()))
                .handle(request, client);
        auditService.success(
                AuditEvent.TOKEN_ISSUED, null, client.getClientId(), "grant_type=" + request.grantType());
        return response;
    }
}
