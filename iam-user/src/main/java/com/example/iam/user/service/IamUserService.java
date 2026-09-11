package com.example.iam.user.service;

import com.example.iam.user.context.UserContext;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UpdateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.entity.IamUserEntity;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamUserService {

    UserResponse create(CreateUserRequest request);

    UserResponse update(UUID subjectId, UpdateUserRequest request);

    UserResponse get(UUID subjectId);

    Page<UserResponse> search(String query, String status, String tenantId, Pageable pageable);

    UserResponse disable(UUID subjectId);

    UserResponse enable(UUID subjectId);

    IamUserEntity requireUser(UUID subjectId);

    IamUserEntity requireActiveByUsernameAndTenantId(String username, String tenantId);

    IamUserEntity authenticatePassword(String username, String tenantId, String rawPassword);

    UserContext requireActiveForToken(UUID subjectId);
}
