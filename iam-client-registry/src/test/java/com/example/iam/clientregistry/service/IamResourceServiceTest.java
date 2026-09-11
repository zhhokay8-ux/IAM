package com.example.iam.clientregistry.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.service.impl.IamResourceServiceImpl;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamResourceServiceTest {

    @Mock
    private IamResourceServerRepository resourceRepository;

    private IamResourceService service;

    @BeforeEach
    void setUp() {
        service = new IamResourceServiceImpl(resourceRepository);
    }

    @Test
    void disableSetsInactive() {
        IamResourceServerEntity entity = IamResourceServerEntity.builder()
                .id(UUID.randomUUID())
                .resourceCode("SYSTEM_N")
                .resourceName("N")
                .audience("aud")
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
        when(resourceRepository.findByResourceCode("SYSTEM_N")).thenReturn(Optional.of(entity));
        when(resourceRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertEquals(RegistryStatus.INACTIVE, service.disable("SYSTEM_N").status());
    }
}
