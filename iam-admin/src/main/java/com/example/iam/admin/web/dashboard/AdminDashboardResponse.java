package com.example.iam.admin.web.dashboard;

import com.example.iam.audit.IamAuditLogView;
import com.example.iam.audit.IamAuditTrendRow;
import java.util.List;

public record AdminDashboardResponse(
        AdminDashboardCounts counts,
        AdminDashboardTrends trends,
        List<IamAuditLogView> recentAdminOperations) {

    public record AdminDashboardCounts(
            long clientCount,
            long activeClientCount,
            long resourceCount,
            long scopeCount,
            long userCount,
            long activeSessionCount,
            boolean activeSessionApproximate,
            boolean activeSessionFromCache,
            long activeRefreshTokenCount) {}

    public record AdminDashboardTrends(
            int days,
            List<IamAuditTrendRow> buckets,
            List<DailyMetric> login,
            List<DailyMetric> tokenIssued,
            List<DailyMetric> tokenExchange,
            List<DailyMetric> failure) {}

    public record DailyMetric(String day, long count) {}
}
