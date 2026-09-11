package com.example.iam.clientregistry.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamClientResourcePermissionRepository;
import com.example.iam.clientregistry.service.impl.IamPermissionServiceImpl;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamPermissionServiceTest {

    @Mock
    private IamClientResourcePermissionRepository permissionRepository;

    @Mock
    private IamClientService clientService;

    @Mock
    private IamResourceService resourceService;

    @Mock
    private IamScopeService scopeService;

    private IamPermissionService service;
    private IamClientEntity client;
    private IamResourceServerEntity resource;
    private IamScopeEntity scope;

    @BeforeEach
    void setUp() {
        service = new IamPermissionServiceImpl(permissionRepository, clientService, resourceService, scopeService);
        client = IamClientEntity.builder()
                .id(UUID.randomUUID())
                .clientId("system-1")
                .clientName("System 1")
                .clientType("confidential")
                .status(RegistryStatus.ACTIVE)
                .tokenEndpointAuthMethod("client_secret_basic")
                .accessTokenTtl(600)
                .refreshTokenTtl(86400)
                .pkceRequired(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
        resource = IamResourceServerEntity.builder()
                .id(UUID.randomUUID())
                .resourceCode("SYSTEM_N")
                .resourceName("System N")
                .audience("system-n-api")
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
        scope = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(resource.getId())
                .scopeCode("order.read")
                .scopeName("Order Read")
                .status(RegistryStatus.ACTIVE)
                .build();
    }

    @Test
    void getThrowsWhenPermissionMissing() {
        stubLookups();
        when(permissionRepository.findByClientIdAndResourceIdAndScopeIdAndGrantType(
                        client.getId(), resource.getId(), scope.getId(), GrantType.TOKEN_EXCHANGE.name()))
                .thenReturn(Optional.empty());

        IamException ex = assertThrows(
                IamException.class,
                () -> service.get("system-1", "SYSTEM_N", "order.read", "TOKEN_EXCHANGE"));
        assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
    }

    @Test
    void createHappyPath() {
        stubLookups();
        when(permissionRepository.findByClientIdAndResourceIdAndScopeIdAndGrantType(
                        client.getId(), resource.getId(), scope.getId(), GrantType.AUTHORIZATION_CODE.name()))
                .thenReturn(Optional.empty());
        when(permissionRepository.save(any())).thenAnswer(invocation -> {
            var entity = invocation.getArgument(0);
            return entity;
        });

        var response = service.create(new CreatePermissionRequest(
                "system-1", "SYSTEM_N", "order.read", "AUTHORIZATION_CODE", "ACTIVE"));
        assertEquals("AUTHORIZATION_CODE", response.grantType());
        assertEquals("system-n-api", response.audience());
        assertEquals("order.read", response.scopeCode());
    }

    @Test
    void disableSetsInactive() {
        stubLookups();
        var entity = com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity.builder()
                .id(UUID.randomUUID())
                .clientId(client.getId())
                .resourceId(resource.getId())
                .scopeId(scope.getId())
                .grantType(GrantType.CLIENT_CREDENTIALS.name())
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
        when(permissionRepository.findByClientIdAndResourceIdAndScopeIdAndGrantType(
                        client.getId(),
                        resource.getId(),
                        scope.getId(),
                        GrantType.CLIENT_CREDENTIALS.name()))
                .thenReturn(Optional.of(entity));
        when(permissionRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertEquals(
                RegistryStatus.INACTIVE,
                service.disable("system-1", "SYSTEM_N", "order.read", "client_credentials").status());
    }

    private void stubLookups() {
        when(clientService.requireActiveClient("system-1")).thenReturn(client);
        when(resourceService.requireActiveByCode("SYSTEM_N")).thenReturn(resource);
        when(scopeService.requireBoundScope("SYSTEM_N", "order.read")).thenReturn(scope);
    }
}
