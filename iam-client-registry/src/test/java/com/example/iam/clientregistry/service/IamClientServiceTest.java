package com.example.iam.clientregistry.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.impl.IamClientServiceImpl;
import com.example.iam.clientregistry.validation.IamClientValidator;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamClientServiceTest {

    @Mock
    private IamClientRepository clientRepository;

    @Mock
    private IamClientRedirectUriRepository redirectUriRepository;

    private IamClientService service;

    @BeforeEach
    void setUp() {
        service = new IamClientServiceImpl(
                clientRepository,
                redirectUriRepository,
                new IamClientValidator(),
                new IamRedirectUriValidator());
    }

    @Test
    void getThrowsWhenClientIdDoesNotExist() {
        when(clientRepository.findByClientId("missing")).thenReturn(Optional.empty());
        IamException ex = assertThrows(IamException.class, () -> service.get("missing"));
        assertEquals(IamErrorCode.CLIENT_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void requireActiveClientRejectsDisabledClient() {
        when(clientRepository.findByClientId("portal")).thenReturn(Optional.of(client("portal", RegistryStatus.INACTIVE)));
        IamException ex = assertThrows(IamException.class, () -> service.requireActiveClient("portal"));
        assertEquals(IamErrorCode.CLIENT_INACTIVE, ex.getErrorCode());
    }

    @Test
    void createRejectsDuplicateClientId() {
        when(clientRepository.existsByClientId("portal")).thenReturn(true);
        IamException ex = assertThrows(IamException.class, () -> service.create(request("portal")));
        assertEquals(IamErrorCode.DUPLICATE_CLIENT_ID, ex.getErrorCode());
        verify(clientRepository, never()).save(any());
    }

    @Test
    void createPersistsConfidentialClientWithPkceRequired() {
        when(clientRepository.existsByClientId("portal")).thenReturn(false);
        when(clientRepository.save(any())).thenAnswer(invocation -> {
            IamClientEntity entity = invocation.getArgument(0);
            entity.setId(UUID.randomUUID());
            return entity;
        });
        when(redirectUriRepository.findByClientId(any())).thenReturn(List.of());

        var response = service.create(request("portal"));

        assertEquals("portal", response.clientId());
        assertEquals("confidential", response.clientType());
        assertEquals(RegistryStatus.ACTIVE, response.status());
        assertTrue(response.pkceRequired());
        ArgumentCaptor<IamClientEntity> captor = ArgumentCaptor.forClass(IamClientEntity.class);
        verify(clientRepository).save(captor.capture());
        assertEquals("confidential", captor.getValue().getClientType());
    }

    @Test
    void disableSetsInactive() {
        IamClientEntity entity = client("portal", RegistryStatus.ACTIVE);
        when(clientRepository.findByClientId("portal")).thenReturn(Optional.of(entity));
        when(clientRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(redirectUriRepository.findByClientId(any())).thenReturn(List.of());
        var response = service.disable("portal");
        assertEquals(RegistryStatus.INACTIVE, response.status());
    }

    @Test
    void rotateSecretChangesHashAndDoesNotLogPlaintext() {
        IamClientEntity entity = client("portal", RegistryStatus.ACTIVE);
        entity.setClientSecretHash("old-hash");
        when(clientRepository.findByClientId("portal")).thenReturn(Optional.of(entity));
        when(clientRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(redirectUriRepository.findByClientId(any())).thenReturn(List.of());
        var rotated = service.rotateSecret("portal");
        assertTrue(rotated.clientSecret() != null && !rotated.clientSecret().isBlank());
        assertTrue(!rotated.toString().contains(rotated.clientSecret()) || rotated.toString().contains("***"));
        ArgumentCaptor<IamClientEntity> captor = ArgumentCaptor.forClass(IamClientEntity.class);
        verify(clientRepository).save(captor.capture());
        assertTrue(!captor.getValue().getClientSecretHash().equals("old-hash"));
        assertTrue(!captor.getValue().getClientSecretHash().equals(rotated.clientSecret()));
    }

    @Test
    void dynamicRegisterIsForbidden() {
        IamException ex = assertThrows(IamException.class, () -> service.dynamicRegister(request("portal")));
        assertEquals(IamErrorCode.DYNAMIC_REGISTRATION_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void createRequestToStringDoesNotContainSecret() {
        CreateClientRequest request = request("portal");
        assertTrue(request.toString().contains("***"));
        assertTrue(!request.toString().contains("super-secret"));
    }

    private static CreateClientRequest request(String clientId) {
        return new CreateClientRequest(
                clientId,
                "Portal",
                "confidential",
                "ACTIVE",
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput("https://portal.example.com/callback", "LOGIN_CALLBACK")),
                "super-secret");
    }

    private static IamClientEntity client(String clientId, String status) {
        return IamClientEntity.builder()
                .id(UUID.randomUUID())
                .clientId(clientId)
                .clientName("Portal")
                .clientType("confidential")
                .status(status)
                .tokenEndpointAuthMethod("client_secret_basic")
                .accessTokenTtl(600)
                .refreshTokenTtl(86400)
                .pkceRequired(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }
}
