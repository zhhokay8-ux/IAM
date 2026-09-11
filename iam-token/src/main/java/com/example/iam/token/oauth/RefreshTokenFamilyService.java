package com.example.iam.token.oauth;

import com.example.iam.token.entity.IamRefreshTokenEntity;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenFamilyService {

    void revokeFamily(UUID familyId);

    void revokeAllForSubject(UUID subjectId);

    boolean revokePresentedToken(String presentedToken);

    Optional<IamRefreshTokenEntity> findByPresentedToken(String presentedToken);
}
