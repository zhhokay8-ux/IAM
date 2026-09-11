package com.example.iam.common.error;

public enum IamErrorCode {
    INVALID_ARGUMENT("IAM-4000", 400, "Invalid argument"),
    INVALID_REDIRECT_URI("IAM-4001", 400, "Invalid redirect URI"),
    INVALID_CLIENT_TYPE("IAM-4002", 400, "Invalid client type"),
    INVALID_GRANT_TYPE("IAM-4003", 400, "Invalid grant type"),
    INVALID_ORIGIN("IAM-4004", 400, "Invalid origin"),
    UNAUTHORIZED("IAM-4010", 401, "Unauthorized"),
    CLIENT_INACTIVE("IAM-4011", 401, "Client is disabled"),
    FORBIDDEN("IAM-4030", 403, "Forbidden"),
    PERMISSION_DENIED("IAM-4031", 403, "Client is not allowed to access the resource"),
    TOKEN_EXCHANGE_NOT_ALLOWED("IAM-4032", 403, "Token exchange is not allowed"),
    CLIENT_CREDENTIALS_NOT_ALLOWED("IAM-4033", 403, "Client credentials grant is not allowed"),
    DYNAMIC_REGISTRATION_FORBIDDEN("IAM-4034", 403, "Dynamic client registration is disabled"),
    SCOPE_INACTIVE("IAM-4035", 403, "Scope is disabled"),
    USER_INACTIVE("IAM-4036", 403, "User is disabled and cannot obtain a token"),
    NOT_FOUND("IAM-4040", 404, "Resource not found"),
    CLIENT_NOT_FOUND("IAM-4041", 404, "Client not found"),
    RESOURCE_NOT_FOUND("IAM-4042", 404, "Resource server not found"),
    SCOPE_NOT_FOUND("IAM-4043", 404, "Scope not found"),
    AUDIENCE_NOT_FOUND("IAM-4044", 404, "Audience not found"),
    SCOPE_NOT_BOUND("IAM-4045", 404, "Scope is not bound to the resource"),
    REDIRECT_URI_MISMATCH("IAM-4046", 404, "Redirect URI does not match"),
    USER_NOT_FOUND("IAM-4047", 404, "User not found"),
    MAPPING_NOT_FOUND("IAM-4048", 404, "Identity mapping not found"),
    CONFLICT("IAM-4090", 409, "Conflict"),
    DUPLICATE_CLIENT_ID("IAM-4091", 409, "client_id already exists"),
    DUPLICATE_RESOURCE("IAM-4092", 409, "resource_code already exists"),
    DUPLICATE_AUDIENCE("IAM-4093", 409, "audience already exists"),
    DUPLICATE_SCOPE("IAM-4094", 409, "scope_code already exists for resource"),
    DUPLICATE_PERMISSION("IAM-4095", 409, "Permission already exists"),
    DUPLICATE_USERNAME("IAM-4096", 409, "username already exists in tenant"),
    DUPLICATE_IDENTITY_MAPPING("IAM-4097", 409, "system_code + external_user_id already mapped"),
    INVALID_CLIENT("IAM-4006", 400, "invalid_client"),
    INVALID_PKCE("IAM-4007", 400, "Invalid PKCE"),
    UNSUPPORTED_RESPONSE_TYPE("IAM-4008", 400, "unsupported_response_type"),
    INVALID_GRANT("IAM-4013", 400, "invalid_grant"),
    AUTHORIZATION_CODE_EXPIRED("IAM-4014", 400, "Authorization code expired"),
    INVALID_JWT("IAM-4005", 400, "Invalid JWT"),
    INVALID_JWT_SIGNATURE("IAM-4012", 401, "Invalid JWT signature"),
    JWT_EXPIRED("IAM-4015", 401, "JWT expired"),
    JWT_NOT_BEFORE("IAM-4016", 401, "JWT is not yet valid"),
    INVALID_JWT_ISSUER("IAM-4017", 401, "Invalid JWT issuer"),
    INVALID_JWT_AUDIENCE("IAM-4018", 401, "Invalid JWT audience"),
    TOKEN_REVOKED("IAM-4019", 401, "Token has been revoked"),
    INVALID_CREDENTIALS("IAM-4020", 401, "Invalid username or password"),
    SESSION_NOT_FOUND("IAM-4050", 401, "SSO session not found"),
    SESSION_EXPIRED("IAM-4051", 401, "SSO session expired"),
    SESSION_REVOKED("IAM-4052", 401, "SSO session revoked"),
    INVALID_SSO_COOKIE("IAM-4053", 401, "SSO cookie is invalid"),
    INVALID_ACTOR("IAM-4054", 401, "Invalid actor token"),
    ACTOR_UNAUTHORIZED("IAM-4055", 403, "Actor is not authorized for token exchange"),
    EMBED_CODE_NOT_FOUND("IAM-4060", 400, "Embed code not found"),
    EMBED_CODE_EXPIRED("IAM-4061", 400, "Embed code expired"),
    EMBED_CODE_REPLAY("IAM-4062", 400, "Embed code already used"),
    EMBED_POLICY_DISABLED("IAM-4063", 403, "Embed policy is disabled"),
    EMBED_PATH_NOT_ALLOWED("IAM-4064", 403, "Embed path is not allowed"),
    EMBED_CLIENT_MISMATCH("IAM-4065", 403, "Embed code client mismatch"),
    EMBED_NONCE_MISMATCH("IAM-4066", 400, "Embed nonce mismatch"),
    EMBED_SESSION_MISMATCH("IAM-4067", 401, "Embed session is invalid"),
    INVALID_LOGOUT_TOKEN("IAM-4068", 400, "Invalid logout token"),
    INTROSPECTION_UNAVAILABLE("IAM-5031", 503, "Token introspection is unavailable"),
    INSUFFICIENT_SCOPE("IAM-4038", 403, "Insufficient scope"),
    INSUFFICIENT_ROLE("IAM-4039", 403, "Insufficient role"),
    NO_ACTIVE_SIGNING_KEY("IAM-5030", 503, "No active signing key"),
    SIGNING_KEY_NOT_FOUND("IAM-4049", 404, "Signing key not found"),
    SIGNING_KEY_RETIRED("IAM-4037", 403, "Signing key is retired"),
    RATE_LIMITED("IAM-4290", 429, "Too many requests"),
    MIGRATION_DISABLED("IAM-4070", 403, "IAM migration is disabled"),
    MIGRATION_TICKET_NOT_FOUND("IAM-4071", 400, "Migration ticket not found"),
    MIGRATION_TICKET_EXPIRED("IAM-4072", 400, "Migration ticket expired"),
    MIGRATION_TICKET_REPLAY("IAM-4073", 400, "Migration ticket already used"),
    MIGRATION_CLIENT_MISMATCH("IAM-4074", 403, "Migration ticket client mismatch"),
    MIGRATION_USER_MISMATCH("IAM-4075", 403, "Migration ticket user mismatch"),
    MIGRATION_BROWSER_MISMATCH("IAM-4076", 401, "Migration browser/session mismatch"),
    MIGRATION_NONCE_MISMATCH("IAM-4077", 400, "Migration nonce mismatch"),
    MIGRATION_LEGACY_IN_URL("IAM-4078", 400, "Legacy session must not be sent in the URL"),
    CSRF_INVALID("IAM-4079", 403, "CSRF validation failed"),
    ADMIN_PERMISSION_DENIED("IAM-4081", 403, "Admin permission denied"),
    ADMIN_ROLE_REQUIRED("IAM-4082", 403, "Admin role required"),
    TOKEN_IN_URL("IAM-4080", 400, "access_token must not appear in the URL"),
    INTERNAL_ERROR("IAM-5000", 500, "Internal server error");

    private final String code;
    private final int httpStatus;
    private final String message;

    IamErrorCode(String code, int httpStatus, String message) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getMessage() {
        return message;
    }
}
