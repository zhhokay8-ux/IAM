package com.example.iam.admin.web.audit;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditLogView;
import com.example.iam.audit.IamAuditQuery;
import com.example.iam.audit.IamAuditService;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/audit")
public class AdminAuditController {

    private final IamAuditService auditService;

    public AdminAuditController(IamAuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/events")
    @RequireAdminPermission(AdminPermissions.AUDIT_READ)
    public List<String> events() {
        return Arrays.stream(AuditEvent.values()).map(Enum::name).toList();
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.AUDIT_READ)
    public AdminPageResponse<IamAuditLogView> search(
            @RequestParam(name = "from", required = false) Instant from,
            @RequestParam(name = "to", required = false) Instant to,
            @RequestParam(name = "operator", required = false) String operator,
            @RequestParam(name = "subject", required = false) UUID subjectId,
            @RequestParam(name = "tenant", required = false) String tenantId,
            @RequestParam(name = "event_type", required = false) String eventType,
            @RequestParam(name = "resource_type", required = false) String resourceType,
            @RequestParam(name = "resource_id", required = false) UUID resourceId,
            @RequestParam(name = "success", required = false) Boolean success,
            @RequestParam(name = "trace_id", required = false) String traceId,
            @RequestParam(name = "ip", required = false) String sourceIp,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<IamAuditLogView> result = auditService.search(
                new IamAuditQuery(
                        from,
                        to,
                        operator,
                        subjectId,
                        tenantId,
                        eventType,
                        resourceType,
                        resourceId,
                        success,
                        traceId,
                        sourceIp),
                PageRequest.of(
                        Math.max(page, 0),
                        Math.min(Math.max(size, 1), 100),
                        Sort.by(Sort.Direction.DESC, "createdAt")));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{id}")
    @RequireAdminPermission(AdminPermissions.AUDIT_READ)
    public IamAuditLogView get(@PathVariable("id") UUID id) {
        return auditService.get(id);
    }
}
