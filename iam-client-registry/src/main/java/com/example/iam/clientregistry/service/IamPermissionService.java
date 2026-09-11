package com.example.iam.clientregistry.service;

import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.PermissionResponse;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamPermissionService {

    PermissionResponse create(CreatePermissionRequest request);

    PermissionResponse get(String clientId, String resourceCode, String scopeCode, String grantType);

    List<PermissionResponse> listByClientId(String clientId);

    Page<PermissionResponse> search(
            String clientId, String resourceCode, String grantType, String status, Pageable pageable);

    PermissionResponse disable(String clientId, String resourceCode, String scopeCode, String grantType);

    PermissionResponse enable(String clientId, String resourceCode, String scopeCode, String grantType);
}
