package com.example.iam.admin.web.dashboard;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.RequireAdminPermission;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/dashboard")
public class AdminDashboardController {

    private final AdminDashboardService dashboardService;

    public AdminDashboardController(AdminDashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.AUDIT_READ)
    public AdminDashboardResponse snapshot(@RequestParam(name = "days", defaultValue = "7") int days) {
        return dashboardService.snapshot(days);
    }
}
