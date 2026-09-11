package com.example.iam.admin.web.dashboard;

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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AdminDashboardService {

    private static final Set<String> LOGIN_EVENTS =
            Set.of(AuditEvent.LOGIN_SUCCESS.name(), AuditEvent.ADMIN_AUTH_SUCCESS.name());
    private static final int MAX_DAYS = 31;

    private final IamClientRepository clientRepository;
    private final IamResourceServerRepository resourceRepository;
    private final IamScopeRepository scopeRepository;
    private final IamUserRepository userRepository;
    private final IamRefreshTokenRepository refreshTokenRepository;
    private final IamSessionService sessionService;
    private final IamAuditService auditService;
    private final Clock clock;

    @Autowired
    public AdminDashboardService(
            IamClientRepository clientRepository,
            IamResourceServerRepository resourceRepository,
            IamScopeRepository scopeRepository,
            IamUserRepository userRepository,
            IamRefreshTokenRepository refreshTokenRepository,
            IamSessionService sessionService,
            IamAuditService auditService) {
        this(
                clientRepository,
                resourceRepository,
                scopeRepository,
                userRepository,
                refreshTokenRepository,
                sessionService,
                auditService,
                Clock.systemUTC());
    }

    AdminDashboardService(
            IamClientRepository clientRepository,
            IamResourceServerRepository resourceRepository,
            IamScopeRepository scopeRepository,
            IamUserRepository userRepository,
            IamRefreshTokenRepository refreshTokenRepository,
            IamSessionService sessionService,
            IamAuditService auditService,
            Clock clock) {
        this.clientRepository = clientRepository;
        this.resourceRepository = resourceRepository;
        this.scopeRepository = scopeRepository;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.clock = clock;
    }

    public AdminDashboardResponse snapshot(int days) {
        int window = days < 1 ? 7 : Math.min(days, MAX_DAYS);
        Instant to = clock.instant();
        Instant from = to.minus(Duration.ofDays(window));
        SessionCount sessions = sessionService.countActive();
        List<IamAuditTrendRow> buckets = auditService.trend(from, to);
        Page<IamAuditLogView> recent = auditService.recentAdminOperations(
                PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "createdAt")));
        return new AdminDashboardResponse(
                new AdminDashboardResponse.AdminDashboardCounts(
                        clientRepository.count(),
                        clientRepository.countByStatus(RegistryStatus.ACTIVE),
                        resourceRepository.count(),
                        scopeRepository.count(),
                        userRepository.count(),
                        sessions.active(),
                        sessions.approximate(),
                        sessions.fromCache(),
                        refreshTokenRepository.countByStatusAndExpiresAtAfter(
                                RefreshTokenServiceImpl.STATUS_ACTIVE, to)),
                new AdminDashboardResponse.AdminDashboardTrends(
                        window,
                        buckets,
                        rollup(buckets, LOGIN_EVENTS, false),
                        rollup(buckets, Set.of(AuditEvent.TOKEN_ISSUED.name()), false),
                        rollup(buckets, Set.of(AuditEvent.TOKEN_EXCHANGE.name()), false),
                        rollup(buckets, Set.of(), true)),
                recent.getContent());
    }

    static List<AdminDashboardResponse.DailyMetric> rollup(
            List<IamAuditTrendRow> buckets, Set<String> eventTypes, boolean failuresOnly) {
        Map<String, Long> byDay = new LinkedHashMap<>();
        if (buckets != null) {
            for (IamAuditTrendRow row : buckets) {
                if (failuresOnly) {
                    if ("SUCCESS".equals(row.result())) {
                        continue;
                    }
                } else if (!eventTypes.contains(row.eventType())) {
                    continue;
                }
                byDay.merge(row.day(), row.count(), Long::sum);
            }
        }
        List<AdminDashboardResponse.DailyMetric> metrics = new ArrayList<>();
        for (Map.Entry<String, Long> entry : byDay.entrySet()) {
            metrics.add(new AdminDashboardResponse.DailyMetric(entry.getKey(), entry.getValue()));
        }
        metrics.sort((a, b) -> a.day().compareTo(b.day()));
        return metrics;
    }
}
