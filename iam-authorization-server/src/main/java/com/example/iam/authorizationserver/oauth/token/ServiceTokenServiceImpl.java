package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ServiceTokenServiceImpl implements ServiceTokenService {

    private final AccessTokenService accessTokenService;
    private final Clock clock;

    @Autowired
    public ServiceTokenServiceImpl(AccessTokenService accessTokenService) {
        this(accessTokenService, Clock.systemUTC());
    }

    ServiceTokenServiceImpl(AccessTokenService accessTokenService, Clock clock) {
        this.accessTokenService = accessTokenService;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    @Override
    public String issue(IamClientEntity client, List<String> audiences, String scope) {
        return issue(client, audiences, scope, clock.instant());
    }

    @Override
    public String issue(IamClientEntity client, List<String> audiences, String scope, Instant issuedAt) {
        if (client == null || client.getClientId() == null || client.getClientId().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_CLIENT, "client is required");
        }
        if (audiences == null || audiences.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "audience is required");
        }
        Instant iat = issuedAt == null ? clock.instant() : issuedAt;
        Duration ttl = AuthorizationCodeTokenGrantHandler.accessTtl(client);
        Instant exp = iat.plus(ttl);
        return accessTokenService.issue(new AccessTokenClaims(
                ServiceTokenService.subjectFor(client.getClientId()),
                List.copyOf(audiences),
                client.getClientId(),
                scope == null ? "" : scope,
                List.of(),
                null,
                null,
                iat,
                exp,
                null,
                null,
                TOKEN_USE));
    }
}
