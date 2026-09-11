package com.example.iam.sdk;

public final class IamUserContextHolder {

    private static final ThreadLocal<IamUserContext> HOLDER = new ThreadLocal<>();

    private IamUserContextHolder() {
    }

    public static void set(IamUserContext context) {
        HOLDER.set(context);
    }

    public static IamUserContext get() {
        return HOLDER.get();
    }

    public static IamUserContext require() {
        IamUserContext context = get();
        if (context == null) {
            throw new com.example.iam.common.error.IamException(
                    com.example.iam.common.error.IamErrorCode.UNAUTHORIZED, "user context is missing");
        }
        return context;
    }

    public static void clear() {
        HOLDER.remove();
    }
}
