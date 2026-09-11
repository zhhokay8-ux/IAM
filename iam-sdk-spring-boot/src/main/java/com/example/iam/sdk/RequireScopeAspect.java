package com.example.iam.sdk;

import com.example.iam.resourceserver.jwt.ScopeValidator;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

@Aspect
public class RequireScopeAspect {

    private final ScopeValidator scopeValidator = new ScopeValidator();

    @Before("@within(com.example.iam.sdk.RequireScope) || @annotation(com.example.iam.sdk.RequireScope)")
    public void check(JoinPoint joinPoint) {
        RequireScope annotation = resolve(joinPoint);
        if (annotation != null) {
            scopeValidator.validate(IamUserContextHolder.require().getScopes(), annotation.value());
        }
    }

    private static RequireScope resolve(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        RequireScope method = signature.getMethod().getAnnotation(RequireScope.class);
        if (method != null) {
            return method;
        }
        return joinPoint.getTarget().getClass().getAnnotation(RequireScope.class);
    }
}
