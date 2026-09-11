package com.example.iam.user.service;

import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.IdentityMappingResponse;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamIdentityMappingService {

    IdentityMappingResponse create(UUID subjectId, IdentityMappingRequest request);

    IdentityMappingResponse update(UUID mappingId, IdentityMappingRequest request);

    void delete(UUID mappingId);

    IdentityMappingResponse get(UUID mappingId);

    List<IdentityMappingResponse> list(UUID subjectId);

    IdentityMappingResponse requireMapping(String systemCode, String externalUserId);

    Page<IdentityMappingResponse> search(
            String systemCode, String externalUserId, UUID subjectId, Pageable pageable);
}
