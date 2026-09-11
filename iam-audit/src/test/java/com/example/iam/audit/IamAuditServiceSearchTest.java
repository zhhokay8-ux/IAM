package com.example.iam.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;

@ExtendWith(MockitoExtension.class)
class IamAuditServiceSearchTest {

    @Mock
    private IamAuditLogRepository repository;

    private IamAuditService service;

    @BeforeEach
    void setUp() {
        service = new IamAuditService(repository);
    }

    @Test
    void recordSanitizesProtocolDetails() {
        service.success(AuditEvent.TOKEN_ISSUED, null, "portal", "access_token=eyJsecret");
        ArgumentCaptor<IamAuditLogEntity> captor = ArgumentCaptor.forClass(IamAuditLogEntity.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getDetail()).doesNotContain("eyJsecret");
        assertThat(captor.getValue().getDetail()).contains("access_token=***");
    }

    @Test
    void searchAndGetSanitizeStoredSecrets() {
        UUID id = UUID.randomUUID();
        IamAuditLogEntity stored = IamAuditLogEntity.builder()
                .id(id)
                .traceId("tr-1")
                .eventType(AuditEvent.CLIENT_DISABLED.name())
                .result("SUCCESS")
                .detail("client_secret=leaked-secret")
                .failureReason("refresh_token=rt-plain")
                .operatorName("admin")
                .tenantId("admin-cli")
                .resourceType("client")
                .sourceIp("10.0.0.8")
                .userAgent("JUnit")
                .createdAt(Instant.parse("2026-09-11T02:00:00Z"))
                .build();
        when(repository.findAll(any(Specification.class), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(stored), PageRequest.of(0, 20), 1));
        when(repository.findById(id)).thenReturn(Optional.of(stored));

        IamAuditLogView listed = service.search(
                        new IamAuditQuery(
                                null,
                                null,
                                "admin",
                                null,
                                "admin-cli",
                                AuditEvent.CLIENT_DISABLED.name(),
                                "client",
                                null,
                                true,
                                "tr-1",
                                "10.0.0.8"),
                        PageRequest.of(0, 20))
                .getContent()
                .get(0);
        assertThat(listed.detail()).isEqualTo("client_secret=***");
        assertThat(listed.failureReason()).isEqualTo("refresh_token=***");
        assertThat(listed.success()).isTrue();
        assertThat(listed.operatorName()).isEqualTo("admin");
        assertThat(listed.sourceIp()).isEqualTo("10.0.0.8");
        assertThat(listed.traceId()).isEqualTo("tr-1");

        IamAuditLogView detail = service.get(id);
        assertThat(detail.detail()).doesNotContain("leaked-secret");
        assertThat(detail.id()).isEqualTo(id);
    }

    @Test
    void groupsAuditRowsByUtcDayEventAndSuccess() {
        Instant day = Instant.parse("2026-09-10T23:00:00Z");
        IamAuditLogEntity login = IamAuditLogEntity.builder()
                .eventType(AuditEvent.LOGIN_SUCCESS.name())
                .result("SUCCESS")
                .createdAt(day)
                .build();
        IamAuditLogEntity fail = IamAuditLogEntity.builder()
                .eventType(AuditEvent.LOGIN_FAILURE.name())
                .result("FAILURE")
                .createdAt(day.plusSeconds(3600))
                .build();
        IamAuditLogEntity fail2 = IamAuditLogEntity.builder()
                .eventType(AuditEvent.LOGIN_FAILURE.name())
                .result("FAILURE")
                .createdAt(day.plusSeconds(7200))
                .build();
        List<IamAuditTrendRow> grouped = IamAuditService.groupByDayUtc(List.of(login, fail, fail2));
        assertThat(grouped).containsExactly(
                new IamAuditTrendRow("2026-09-10", AuditEvent.LOGIN_SUCCESS.name(), "SUCCESS", 1),
                new IamAuditTrendRow("2026-09-11", AuditEvent.LOGIN_FAILURE.name(), "FAILURE", 2));
    }

    @Test
    void trendUsesNativeRowsWhenPresent() {
        Instant from = Instant.parse("2026-09-01T00:00:00Z");
        Instant to = Instant.parse("2026-09-11T00:00:00Z");
        List<Object[]> nativeRows = new java.util.ArrayList<>();
        nativeRows.add(new Object[] {"2026-09-10", AuditEvent.TOKEN_ISSUED.name(), "SUCCESS", 4});
        when(repository.aggregateByDay(from, to)).thenReturn(nativeRows);
        assertThat(service.trend(from, to))
                .containsExactly(new IamAuditTrendRow("2026-09-10", AuditEvent.TOKEN_ISSUED.name(), "SUCCESS", 4));
    }
}
