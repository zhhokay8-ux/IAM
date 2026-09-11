package com.example.iam.token.oauth;

import com.example.iam.token.entity.IamRefreshTokenEntity;
import java.time.Duration;
import java.util.UUID;

public interface RefreshTokenService {

    IssuedRefreshToken issue(
            UUID userPk,
            UUID clientPk,
            UUID familyId,
            String scope,
            String audience,
            Duration ttl);

    IssuedRefreshToken rotate(String presentedToken, UUID clientPk);

    record IssuedRefreshToken(String token, IamRefreshTokenEntity entity) {
    }
}
