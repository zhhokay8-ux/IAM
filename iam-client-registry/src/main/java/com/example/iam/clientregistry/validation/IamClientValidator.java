package com.example.iam.clientregistry.validation;

import com.example.iam.clientregistry.domain.ClientType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class IamClientValidator {

    private static final Logger log = LoggerFactory.getLogger(IamClientValidator.class);

    public IamClientEntity validateClient(Optional<IamClientEntity> found, String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "client_id is required");
        }
        IamClientEntity client = found.orElseThrow(
                () -> new IamException(IamErrorCode.CLIENT_NOT_FOUND, "client_id not found: " + clientId));
        if (!RegistryStatus.isActive(client.getStatus())) {
            throw new IamException(IamErrorCode.CLIENT_INACTIVE, "client is disabled: " + clientId);
        }
        log.debug("Validated active client {}", client.getClientId());
        return client;
    }

    public String validateClientType(String clientType) {
        return ClientType.normalize(clientType);
    }

    public void rejectDynamicRegistration() {
        throw new IamException(
                IamErrorCode.DYNAMIC_REGISTRATION_FORBIDDEN,
                "Dynamic client registration is disabled in production");
    }

    public void assertSecretNotLogged(String rendered) {
        if (rendered != null && looksLikeSecret(rendered)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "client secret must not appear in logs");
        }
    }

    private static boolean looksLikeSecret(String value) {
        String lower = value.toLowerCase();
        return lower.contains("client_secret") && !lower.contains("***") && !lower.contains("redacted");
    }
}
