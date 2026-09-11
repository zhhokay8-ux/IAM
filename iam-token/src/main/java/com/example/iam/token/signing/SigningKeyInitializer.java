package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class SigningKeyInitializer implements ApplicationRunner {

    private final SigningKeyService signingKeyService;
    private final SigningKeySecretStore secretStore;

    public SigningKeyInitializer(SigningKeyService signingKeyService, SigningKeySecretStore secretStore) {
        this.signingKeyService = signingKeyService;
        this.secretStore = secretStore;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            KeyMetadata active = signingKeyService.getActiveKey();
            secretStore.loadPrivateKey(active.kmsKeyId());
        } catch (IamException ex) {
            if (ex.getErrorCode() != IamErrorCode.NO_ACTIVE_SIGNING_KEY
                    && ex.getErrorCode() != IamErrorCode.SIGNING_KEY_NOT_FOUND) {
                throw ex;
            }
            signingKeyService.createActiveKey();
        }
    }
}
