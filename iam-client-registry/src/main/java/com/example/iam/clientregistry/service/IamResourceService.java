package com.example.iam.clientregistry.service;

import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.dto.UpdateResourceRequest;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamResourceService {

    ResourceResponse create(CreateResourceRequest request);

    ResourceResponse update(String resourceCode, UpdateResourceRequest request);

    ResourceResponse get(String resourceCode);

    ResourceResponse getById(UUID id);

    Page<ResourceResponse> search(String query, String status, Pageable pageable);

    ResourceResponse disable(String resourceCode);

    ResourceResponse enable(String resourceCode);

    IamResourceServerEntity requireActiveByCode(String resourceCode);

    IamResourceServerEntity requireActiveByAudience(String audience);
}
