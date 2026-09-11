package com.example.iam.embed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import com.example.iam.embed.repository.IamEmbedPolicyRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EmbedPolicyServiceTest {

    @Mock
    private IamEmbedPolicyRepository policyRepository;

    @Mock
    private IamClientService clientService;

    @Mock
    private IamClientRepository clientRepository;

    private EmbedPolicyServiceImpl service;
    private IamClientEntity parent;
    private IamClientEntity child;

    @BeforeEach
    void setUp() {
        service = new EmbedPolicyServiceImpl(
                policyRepository, clientService, clientRepository, new OriginValidator(new IamOriginValidator()));
        parent = client("portal");
        child = client("system-n");
        lenient().when(clientService.requireActiveClient("portal")).thenReturn(parent);
        lenient().when(clientService.requireActiveClient("system-n")).thenReturn(child);
    }

    @Test
    void validPolicy() {
        when(policyRepository.findByChildClientIdAndParentClientId(child.getId(), parent.getId()))
                .thenReturn(List.of(policy(RegistryStatus.ACTIVE, "https://portal.example.com", "/orders/*")));
        IamEmbedPolicyEntity matched =
                service.requireActive("portal", "system-n", "https://portal.example.com", "/orders/1");
        assertEquals("/orders/*", matched.getAllowedPath());
    }

    @Test
    void policyDisabled() {
        when(policyRepository.findByChildClientIdAndParentClientId(child.getId(), parent.getId()))
                .thenReturn(List.of(policy(RegistryStatus.INACTIVE, "https://portal.example.com", "/orders")));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.requireActive("portal", "system-n", "https://portal.example.com", "/orders"));
        assertEquals(IamErrorCode.EMBED_POLICY_DISABLED, ex.getErrorCode());
    }

    @Test
    void wrongPath() {
        when(policyRepository.findByChildClientIdAndParentClientId(child.getId(), parent.getId()))
                .thenReturn(List.of(policy(RegistryStatus.ACTIVE, "https://portal.example.com", "/orders")));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.requireActive("portal", "system-n", "https://portal.example.com", "/admin"));
        assertEquals(IamErrorCode.EMBED_PATH_NOT_ALLOWED, ex.getErrorCode());
    }

    @Test
    void wrongOriginHasNoPolicy() {
        when(policyRepository.findByChildClientIdAndParentClientId(child.getId(), parent.getId()))
                .thenReturn(List.of(policy(RegistryStatus.ACTIVE, "https://portal.example.com", "/orders")));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.requireActive("portal", "system-n", "https://evil.example.com", "/orders"));
        assertEquals(IamErrorCode.FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void createRejectsWildcardOrigin() {
        stubClientsForCreate();
        IamException ex = assertThrows(
                IamException.class, () -> service.create("portal", "system-n", "*", "/orders"));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void createRejectsBareWildcardPath() {
        stubClientsForCreate();
        IamException ex = assertThrows(
                IamException.class,
                () -> service.create("portal", "system-n", "https://portal.example.com", "*"));
        assertEquals(IamErrorCode.EMBED_PATH_NOT_ALLOWED, ex.getErrorCode());
    }

    private void stubClientsForCreate() {
        Instant now = Instant.now();
        when(clientService.get("portal"))
                .thenReturn(new ClientResponse(
                        parent.getId(),
                        "portal",
                        "P",
                        "confidential",
                        "ACTIVE",
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(),
                        now,
                        now));
        when(clientService.get("system-n"))
                .thenReturn(new ClientResponse(
                        child.getId(),
                        "system-n",
                        "C",
                        "confidential",
                        "ACTIVE",
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(),
                        now,
                        now));
    }

    private IamEmbedPolicyEntity policy(String status, String origin, String path) {
        return IamEmbedPolicyEntity.builder()
                .id(UUID.randomUUID())
                .parentClientId(parent.getId())
                .childClientId(child.getId())
                .parentOrigin(origin)
                .allowedPath(path)
                .status(status)
                .createdAt(Instant.now())
                .build();
    }

    private static IamClientEntity client(String clientId) {
        IamClientEntity entity = new IamClientEntity();
        entity.setId(UUID.randomUUID());
        entity.setClientId(clientId);
        entity.setStatus(RegistryStatus.ACTIVE);
        return entity;
    }
}
