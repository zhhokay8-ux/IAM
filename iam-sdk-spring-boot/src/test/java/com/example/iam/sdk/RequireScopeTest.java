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

class RequireScopeTest {

    private final RequireScopeAspect aspect = new RequireScopeAspect();

    @AfterEach
    void tearDown() {
        IamUserContextHolder.clear();
    }

    @Test
    void allowsMatchingScope() throws Exception {
        IamUserContextHolder.set(context("order.read"));
        assertDoesNotThrow(() -> aspect.check(joinPoint(Annotated.class.getDeclaredMethod("read"))));
    }

    @Test
    void rejectsMissingScope() throws Exception {
        IamUserContextHolder.set(context("profile"));
        IamException ex = assertThrows(
                IamException.class, () -> aspect.check(joinPoint(Annotated.class.getDeclaredMethod("read"))));
        assertEquals(IamErrorCode.INSUFFICIENT_SCOPE, ex.getErrorCode());
    }

    private static IamUserContext context(String scope) {
        return new IamUserContext("u1", "alice", "t1", "o1", List.of(), List.of(scope), "c1");
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
        @RequireScope("order.read")
        void read() {}
    }
}
