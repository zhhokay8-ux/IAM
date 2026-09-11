package com.example.iam.admin.web.dashboard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditLogView;
import com.example.iam.audit.IamAuditService;
import com.example.iam.audit.IamAuditTrendRow;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.session.IamSessionService;
import com.example.iam.session.SessionCount;
import com.example.iam.token.oauth.RefreshTokenServiceImpl;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import com.example.iam.user.repository.IamUserRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

@ExtendWith(MockitoExtension.class)
class AdminDashboardServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-11T02:00:00Z");

    @Mock
    private IamClientRepository clientRepository;

    @Mock
    private IamResourceServerRepository resourceRepository;

    @Mock
    private IamScopeRepository scopeRepository;

    @Mock
    private IamUserRepository userRepository;

    @Mock
    private IamRefreshTokenRepository refreshTokenRepository;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private IamAuditService auditService;

    private AdminDashboardService service;

    @BeforeEach
    void setUp() {
        service = new AdminDashboardService(
                clientRepository,
                resourceRepository,
                scopeRepository,
                userRepository,
                refreshTokenRepository,
                sessionService,
                auditService,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void snapshotReadsExistingTablesAndRollsAuditTrends() {
        when(clientRepository.count()).thenReturn(4L);
        when(clientRepository.countByStatus(RegistryStatus.ACTIVE)).thenReturn(3L);
        when(resourceRepository.count()).thenReturn(2L);
        when(scopeRepository.count()).thenReturn(5L);
        when(userRepository.count()).thenReturn(9L);
        when(sessionService.countActive()).thenReturn(new SessionCount(6, false, true));
        when(refreshTokenRepository.countByStatusAndExpiresAtAfter(RefreshTokenServiceImpl.STATUS_ACTIVE, NOW))
                .thenReturn(7L);
        when(auditService.trend(any(), any()))
                .thenReturn(List.of(
                        new IamAuditTrendRow("2026-09-11", AuditEvent.LOGIN_SUCCESS.name(), "SUCCESS", 2),
                        new IamAuditTrendRow("2026-09-11", AuditEvent.TOKEN_ISSUED.name(), "SUCCESS", 3),
                        new IamAuditTrendRow("2026-09-11", AuditEvent.TOKEN_EXCHANGE.name(), "SUCCESS", 1),
                        new IamAuditTrendRow("2026-09-11", AuditEvent.LOGIN_FAILURE.name(), "FAILURE", 4)));
        IamAuditLogView recent = new IamAuditLogView(
                UUID.randomUUID(),
                "tr",
                AuditEvent.CLIENT_DISABLED.name(),
                null,
                null,
                null,
                "client",
                null,
                null,
                "SUCCESS",
                true,
                null,
                "admin_disable_client",
                "tester",
                "admin-cli",
                NOW);
        when(auditService.recentAdminOperations(any())).thenReturn(new PageImpl<>(List.of(recent), PageRequest.of(0, 20), 1));

        AdminDashboardResponse snapshot = service.snapshot(7);

        assertThat(snapshot.counts().clientCount()).isEqualTo(4);
        assertThat(snapshot.counts().activeClientCount()).isEqualTo(3);
        assertThat(snapshot.counts().resourceCount()).isEqualTo(2);
        assertThat(snapshot.counts().scopeCount()).isEqualTo(5);
        assertThat(snapshot.counts().userCount()).isEqualTo(9);
        assertThat(snapshot.counts().activeSessionCount()).isEqualTo(6);
        assertThat(snapshot.counts().activeSessionFromCache()).isTrue();
        assertThat(snapshot.counts().activeRefreshTokenCount()).isEqualTo(7);
        assertThat(snapshot.trends().login()).containsExactly(new AdminDashboardResponse.DailyMetric("2026-09-11", 2));
        assertThat(snapshot.trends().tokenIssued()).containsExactly(new AdminDashboardResponse.DailyMetric("2026-09-11", 3));
        assertThat(snapshot.trends().tokenExchange()).containsExactly(new AdminDashboardResponse.DailyMetric("2026-09-11", 1));
        assertThat(snapshot.trends().failure()).containsExactly(new AdminDashboardResponse.DailyMetric("2026-09-11", 4));
        assertThat(snapshot.recentAdminOperations()).containsExactly(recent);
    }
}
