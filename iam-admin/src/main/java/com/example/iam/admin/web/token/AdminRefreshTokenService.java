package com.example.iam.admin.web.token;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.IamUserService;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AdminRefreshTokenService {

    private final IamRefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final IamUserService userService;
    private final IamUserRepository userRepository;

    public AdminRefreshTokenService(
            IamRefreshTokenRepository refreshTokenRepository,
            RefreshTokenFamilyService refreshTokenFamilyService,
            IamUserService userService,
            IamUserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
        this.userService = userService;
        this.userRepository = userRepository;
    }

    public AdminRefreshTokenResponse get(UUID id) {
        return toResponse(require(id));
    }

    public List<AdminRefreshTokenResponse> listByJwtSubject(UUID subjectId) {
        UserResponse user = userService.get(subjectId);
        return refreshTokenRepository.findBySubjectId(user.id()).stream()
                .map(entity -> AdminRefreshTokenResponse.from(entity, user.subjectId()))
                .toList();
    }

    public List<AdminRefreshTokenResponse> listByFamily(UUID familyId) {
        return refreshTokenRepository.findBySessionId(familyId).stream().map(this::toResponse).toList();
    }

    public AdminRefreshTokenResponse revokeById(UUID id) {
        IamRefreshTokenEntity entity = require(id);
        refreshTokenFamilyService.revokeFamily(entity.getSessionId());
        return toResponse(require(id));
    }

    public void revokeByJwtSubject(UUID subjectId) {
        UserResponse user = userService.get(subjectId);
        refreshTokenFamilyService.revokeAllForSubject(user.id());
    }

    public void revokeFamily(UUID familyId) {
        refreshTokenFamilyService.revokeFamily(familyId);
    }

    private IamRefreshTokenEntity require(UUID id) {
        return refreshTokenRepository
                .findById(id)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "refresh token metadata not found"));
    }

    private AdminRefreshTokenResponse toResponse(IamRefreshTokenEntity entity) {
        String jwtSubject = userRepository
                .findById(entity.getSubjectId())
                .map(IamUserEntity::getSubjectId)
                .map(UUID::toString)
                .orElse(null);
        return AdminRefreshTokenResponse.from(entity, jwtSubject);
    }
}
