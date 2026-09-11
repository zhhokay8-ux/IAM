package com.example.iam.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamAuditServiceAdminTest {

    @Mock
    private IamAuditLogRepository repository;

    @Test
    void recordAdminRedactsSecrets() {
        IamAuditService service = new IamAuditService(repository);
        service.recordAdmin(
                AuditEvent.ADMIN_WRITE,
                "11111111-1111-1111-1111-111111111111",
                "admin",
                "tenant-a",
                "client",
                "cid",
                "127.0.0.1",
                "JUnit",
                true,
                "client_secret=super-secret access_token=abc refresh_token=def private_key=pem authorization_code=zz code_verifier=pkce cookie=sid");

        ArgumentCaptor<IamAuditLogEntity> captor = ArgumentCaptor.forClass(IamAuditLogEntity.class);
        verify(repository).save(captor.capture());
        IamAuditLogEntity entity = captor.getValue();
        assertThat(entity.getDetail()).doesNotContain("super-secret");
        assertThat(entity.getDetail()).contains("client_secret=***");
        assertThat(entity.getDetail()).contains("access_token=***");
        assertThat(entity.getDetail()).contains("refresh_token=***");
        assertThat(entity.getDetail()).contains("private_key=***");
        assertThat(entity.getDetail()).contains("authorization_code=***");
        assertThat(entity.getDetail()).contains("code_verifier=***");
        assertThat(entity.getDetail()).contains("cookie=***");
        assertThat(IamAuditService.sanitize("token=eyJhbGciOi.secret")).isEqualTo("token=***");
        assertThat(entity.getOperatorName()).isEqualTo("admin");
        assertThat(entity.getTenantId()).isEqualTo("tenant-a");
        assertThat(entity.getResourceType()).isEqualTo("client");
        assertThat(entity.getEventType()).isEqualTo("ADMIN_WRITE");
    }

    @Test
    void sanitizeDirectly() {
        assertThat(IamAuditService.sanitize("keep client_secret: xyz; ok"))
                .isEqualTo("keep client_secret=***; ok");
    }
}
