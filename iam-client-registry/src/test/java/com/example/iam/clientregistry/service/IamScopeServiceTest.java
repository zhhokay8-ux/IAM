package com.example.iam.clientregistry.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.service.impl.IamScopeServiceImpl;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamScopeServiceTest {

    @Mock
    private IamScopeRepository scopeRepository;

    @Mock
    private IamResourceService resourceService;

    private IamScopeService service;
    private IamResourceServerEntity resource;

    @BeforeEach
    void setUp() {
        service = new IamScopeServiceImpl(scopeRepository, resourceService);
        resource = IamResourceServerEntity.builder()
                .id(UUID.randomUUID())
                .resourceCode("SYSTEM_N")
                .resourceName("System N")
                .audience("system-n-api")
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
    }

    @Test
    void requireBoundScopeWhenScopeDoesNotExist() {
        when(resourceService.requireActiveByCode("SYSTEM_N")).thenReturn(resource);
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), "missing")).thenReturn(Optional.empty());
        when(scopeRepository.findByScopeCode("missing")).thenReturn(List.of());

        IamException ex = assertThrows(IamException.class, () -> service.requireBoundScope("SYSTEM_N", "missing"));
        assertEquals(IamErrorCode.SCOPE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void requireBoundScopeWhenScopeBelongsToAnotherResource() {
        when(resourceService.requireActiveByCode("SYSTEM_N")).thenReturn(resource);
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), "order.read")).thenReturn(Optional.empty());
        IamScopeEntity other = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(UUID.randomUUID())
                .scopeCode("order.read")
                .scopeName("Order Read")
                .status(RegistryStatus.ACTIVE)
                .build();
        when(scopeRepository.findByScopeCode("order.read")).thenReturn(List.of(other));

        IamException ex = assertThrows(IamException.class, () -> service.requireBoundScope("SYSTEM_N", "order.read"));
        assertEquals(IamErrorCode.SCOPE_NOT_BOUND, ex.getErrorCode());
    }

    @Test
    void requireBoundScopeRejectsInactiveScope() {
        when(resourceService.requireActiveByCode("SYSTEM_N")).thenReturn(resource);
        IamScopeEntity inactive = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(resource.getId())
                .scopeCode("order.read")
                .scopeName("Order Read")
                .status(RegistryStatus.INACTIVE)
                .build();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), "order.read"))
                .thenReturn(Optional.of(inactive));

        IamException ex = assertThrows(IamException.class, () -> service.requireBoundScope("SYSTEM_N", "order.read"));
        assertEquals(IamErrorCode.SCOPE_INACTIVE, ex.getErrorCode());
    }

    @Test
    void disableSetsInactiveWithoutRequireActive() {
        ResourceResponse response = new ResourceResponse(
                resource.getId(),
                resource.getResourceCode(),
                resource.getResourceName(),
                resource.getAudience(),
                resource.getStatus(),
                resource.getOwner(),
                resource.getCreatedAt());
        when(resourceService.get("SYSTEM_N")).thenReturn(response);
        IamScopeEntity active = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(resource.getId())
                .scopeCode("order.read")
                .scopeName("Order Read")
                .status(RegistryStatus.ACTIVE)
                .build();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), "order.read"))
                .thenReturn(Optional.of(active));
        when(scopeRepository.save(org.mockito.ArgumentMatchers.any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertEquals(RegistryStatus.INACTIVE, service.disable("SYSTEM_N", "order.read").status());
    }

    @Test
    void createBindsScopeToResource() {
        when(resourceService.requireActiveByCode("SYSTEM_N")).thenReturn(resource);
        when(scopeRepository.existsByResourceIdAndScopeCode(resource.getId(), "order.read")).thenReturn(false);
        when(scopeRepository.save(org.mockito.ArgumentMatchers.any())).thenAnswer(invocation -> {
            IamScopeEntity entity = invocation.getArgument(0);
            entity.setId(UUID.randomUUID());
            return entity;
        });

        var response = service.create(new CreateScopeRequest(
                "SYSTEM_N", "order.read", "Order Read", "read orders", "ACTIVE"));
        assertEquals("order.read", response.scopeCode());
        assertEquals("SYSTEM_N", response.resourceCode());
        assertEquals(resource.getId(), response.resourceId());
    }
}
