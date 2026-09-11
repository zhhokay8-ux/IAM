package com.example.iam.sdk;

import com.example.iam.resourceserver.jwt.RoleValidator;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

@Aspect
public class RequireRoleAspect {

    private final RoleValidator roleValidator = new RoleValidator();

    @Before("@within(com.example.iam.sdk.RequireRole) || @annotation(com.example.iam.sdk.RequireRole)")
    public void check(JoinPoint joinPoint) {
        RequireRole annotation = resolve(joinPoint);
        if (annotation != null) {
            roleValidator.validate(IamUserContextHolder.require().getRoles(), annotation.value());
        }
    }

    private static RequireRole resolve(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        RequireRole method = signature.getMethod().getAnnotation(RequireRole.class);
        if (method != null) {
            return method;
        }
        return joinPoint.getTarget().getClass().getAnnotation(RequireRole.class);
    }
}
