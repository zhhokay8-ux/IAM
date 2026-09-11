package com.example.iam.admin.web.user;

import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AdminUserLifecycleService {

    private final IamUserService userService;
    private final IamSessionService sessionService;
    private final RefreshTokenFamilyService refreshTokenFamilyService;

    public AdminUserLifecycleService(
            IamUserService userService,
            IamSessionService sessionService,
            RefreshTokenFamilyService refreshTokenFamilyService) {
        this.userService = userService;
        this.sessionService = sessionService;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
    }

    public UserResponse disable(UUID subjectId) {
        UserResponse user = userService.disable(subjectId);
        sessionService.revokeAllForSubject(subjectId.toString());
        refreshTokenFamilyService.revokeAllForSubject(user.id());
        return user;
    }

    public UserResponse enable(UUID subjectId) {
        return userService.enable(subjectId);
    }
}
