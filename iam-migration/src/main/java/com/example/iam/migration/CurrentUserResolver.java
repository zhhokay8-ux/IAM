package com.example.iam.migration;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.session.IamSession;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CurrentUserResolver {

    private final MigrationProperties properties;
    private final IdentityMappingResolver mappingResolver;

    public CurrentUserResolver(MigrationProperties properties, IdentityMappingResolver mappingResolver) {
        this.properties = properties;
        this.mappingResolver = mappingResolver;
    }

    public CurrentUser resolve(Optional<IamSession> iamSession, Optional<LegacyPrincipal> legacyPrincipal) {
        if (properties.iamLoginEnabled() && iamSession != null && iamSession.isPresent()) {
            IamSession session = iamSession.get();
            return new CurrentUser(session.subjectId(), null, null, List.of());
        }
        if (properties.legacyLoginEnabled() && legacyPrincipal != null && legacyPrincipal.isPresent()) {
            LegacyPrincipal legacy = legacyPrincipal.get();
            if (properties.iamLoginEnabled()) {
                var mapping = mappingResolver.resolve(legacy.systemCode(), legacy.externalUserId(), null);
                return new CurrentUser(
                        mapping.subjectId(),
                        firstNonBlank(legacy.username(), mapping.externalUsername()),
                        legacy.tenantId(),
                        legacy.roles());
            }
            return new CurrentUser(
                    "legacy:" + legacy.externalUserId(),
                    legacy.username(),
                    legacy.tenantId(),
                    legacy.roles());
        }
        throw new IamException(IamErrorCode.UNAUTHORIZED, "no current user");
    }

    public CurrentUser fromLegacyOnly(LegacyPrincipal legacy) {
        if (!properties.legacyLoginEnabled()) {
            throw new IamException(IamErrorCode.MIGRATION_DISABLED, "legacy login is disabled");
        }
        return resolve(Optional.empty(), Optional.ofNullable(legacy));
    }

    static String browserBinding(String legacySessionCookie) {
        if (!StringUtils.hasText(legacySessionCookie)) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "legacy session is required");
        }
        return HashUtils.sha256Hex(legacySessionCookie);
    }

    private static String firstNonBlank(String left, String right) {
        if (StringUtils.hasText(left)) {
            return left;
        }
        return right;
    }
}
