package com.example.iam.admin.web;

import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminMeController {

    @GetMapping("/me")
    public AdminMeResponse me(HttpServletRequest request) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        return new AdminMeResponse(
                principal.subjectId(),
                principal.username(),
                principal.tenantId(),
                principal.authMethod().name(),
                new LinkedHashSet<>(principal.roles()),
                new LinkedHashSet<>(principal.permissions()));
    }

    public record AdminMeResponse(
            UUID subjectId,
            String username,
            String tenantId,
            String authMethod,
            Set<String> roles,
            Set<String> permissions) {}
}
