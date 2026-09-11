package com.example.iam.admin.web.config;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.RequireAdminPermission;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/config")
public class AdminConfigController {

    private final AdminConfigService configService;

    public AdminConfigController(AdminConfigService configService) {
        this.configService = configService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.CONFIG_READ)
    public AdminConfigResponse snapshot() {
        return configService.snapshot();
    }

    @RequestMapping(method = {RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
    @RequireAdminPermission(AdminPermissions.CONFIG_READ)
    public AdminConfigResponse mutate() {
        configService.rejectMutation();
        return configService.snapshot();
    }
}
