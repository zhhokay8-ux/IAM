package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.oauth.RefreshTokenService;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.IamUserService;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class RefreshTokenGrantHandler implements TokenGrantHandler {

    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final IamUserRepository userRepository;
    private final IamUserService userService;

    public RefreshTokenGrantHandler(
            RefreshTokenService refreshTokenService,
            AccessTokenService accessTokenService,
            IamUserRepository userRepository,
            IamUserService userService) {
        this.refreshTokenService = refreshTokenService;
        this.accessTokenService = accessTokenService;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @Override
    public boolean supports(String grantType) {
        return "refresh_token".equals(grantType);
    }

    @Override
    public TokenResponse handle(TokenRequest request, IamClientEntity client) {
        RefreshTokenService.IssuedRefreshToken rotated =
                refreshTokenService.rotate(request.refreshToken(), client.getId());
        IamUserEntity user = userRepository
                .findById(rotated.entity().getSubjectId())
                .orElseThrow(() -> new IamException(IamErrorCode.USER_NOT_FOUND, "user not found"));
        UserContext context = userService.requireActiveForToken(user.getSubjectId());
        Instant now = Instant.now();
        Duration ttl = AuthorizationCodeTokenGrantHandler.accessTtl(client);
        Instant exp = now.plus(ttl);
        List<String> audiences = split(rotated.entity().getAudience());
        String scope = rotated.entity().getScope();
        String accessToken = accessTokenService.issue(new AccessTokenClaims(
                context.subjectId(),
                audiences,
                client.getClientId(),
                scope,
                List.of(),
                context.tenantId(),
                context.orgId(),
                now,
                exp,
                null,
                null,
                null));
        return new TokenResponse(
                accessToken, "Bearer", ttl.toSeconds(), rotated.token(), null, scope, null);
    }

    private static List<String> split(String value) {
        if (value == null || value.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh token is missing audience");
        }
        return Arrays.stream(value.trim().split("\\s+")).filter(part -> !part.isBlank()).toList();
    }
}
