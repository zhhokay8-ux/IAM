package com.example.iam.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class UserContextTest {

    @AfterEach
    void tearDown() {
        IamUserContextHolder.clear();
    }

    @Test
    void exposesIdentityAndAuthorizationClaims() {
        IamUserContext context = new IamUserContext(
                "u-1", "alice", "tenant-1", "org-1", List.of("order_admin"), List.of("order.read"), "system-1");
        IamUserContextHolder.set(context);
        IamUserContext current = IamUserContextHolder.require();
        assertEquals("u-1", current.getSubject());
        assertEquals("alice", current.getUsername());
        assertEquals("tenant-1", current.getTenantId());
        assertEquals("org-1", current.getOrgId());
        assertEquals(List.of("order_admin"), current.getRoles());
        assertEquals(List.of("order.read"), current.getScopes());
        assertEquals("system-1", current.getClientId());
    }

    @Test
    void requireWithoutContextIsUnauthorized() {
        IamException ex = assertThrows(IamException.class, IamUserContextHolder::require);
        assertEquals(IamErrorCode.UNAUTHORIZED, ex.getErrorCode());
    }
}
