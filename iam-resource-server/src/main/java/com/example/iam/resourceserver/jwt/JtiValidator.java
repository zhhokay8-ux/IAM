package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;

public class JtiValidator {

    private final boolean enabled;
    private final JtiRevocationStore revocationStore;

    public JtiValidator(boolean enabled, JtiRevocationStore revocationStore) {
        this.enabled = enabled;
        this.revocationStore = revocationStore;
    }

    public void validate(String jti) {
        if (!enabled) {
            return;
        }
        if (jti == null || jti.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_JWT, "jti is required when revocation is enabled");
        }
        try {
            if (revocationStore != null && revocationStore.isRevoked(jti)) {
                throw new IamException(IamErrorCode.TOKEN_REVOKED, "jti has been revoked");
            }
        } catch (IamException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new IamException(IamErrorCode.INTROSPECTION_UNAVAILABLE, "token introspection is unavailable", ex);
        }
    }
}
