package com.example.iam.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.lang.reflect.Method;
import java.util.List;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RequireRoleTest {

    private final RequireRoleAspect aspect = new RequireRoleAspect();

    @AfterEach
    void tearDown() {
        IamUserContextHolder.clear();
    }

    @Test
    void allowsMatchingRole() throws Exception {
        IamUserContextHolder.set(context("order_admin"));
        assertDoesNotThrow(() -> aspect.check(joinPoint(Annotated.class.getDeclaredMethod("admin"))));
    }

    @Test
    void rejectsMissingRole() throws Exception {
        IamUserContextHolder.set(context("viewer"));
        IamException ex = assertThrows(
                IamException.class, () -> aspect.check(joinPoint(Annotated.class.getDeclaredMethod("admin"))));
        assertEquals(IamErrorCode.INSUFFICIENT_ROLE, ex.getErrorCode());
    }

    private static IamUserContext context(String role) {
        return new IamUserContext("u1", "alice", "t1", "o1", List.of(role), List.of(), "c1");
    }

    private static JoinPoint joinPoint(Method method) {
        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature signature = mock(MethodSignature.class);
        when(signature.getMethod()).thenReturn(method);
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getTarget()).thenReturn(new Annotated());
        return joinPoint;
    }

    static class Annotated {
        @RequireRole("order_admin")
        void admin() {}
    }
}
