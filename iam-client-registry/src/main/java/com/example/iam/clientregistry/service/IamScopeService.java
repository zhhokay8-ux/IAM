package com.example.iam.clientregistry.service;

import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.ScopeResponse;
import com.example.iam.clientregistry.dto.UpdateScopeRequest;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamScopeService {

    ScopeResponse create(CreateScopeRequest request);

    ScopeResponse update(String resourceCode, String scopeCode, UpdateScopeRequest request);

    ScopeResponse get(String resourceCode, String scopeCode);

    Page<ScopeResponse> search(String resourceCode, String query, String status, Pageable pageable);

    ScopeResponse disable(String resourceCode, String scopeCode);

    ScopeResponse enable(String resourceCode, String scopeCode);

    IamScopeEntity requireBoundScope(String resourceCode, String scopeCode);
}
