package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class SigningKeyInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyInitializer.class);

    private final SigningKeyService signingKeyService;
    private final SigningKeySecretStore secretStore;
    private final IamSigningKeyRepository signingKeyRepository;

    public SigningKeyInitializer(
            SigningKeyService signingKeyService,
            SigningKeySecretStore secretStore,
            IamSigningKeyRepository signingKeyRepository) {
        this.signingKeyService = signingKeyService;
        this.secretStore = secretStore;
        this.signingKeyRepository = signingKeyRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        retireKeysMissingLocalMaterial();
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

    /**
     * LocalSigningKeySecretStore 只把私钥放在 JVM 内存。进程重启后库里仍有 ACTIVE 元数据，
     * 材料已丢。若不退役这些行，JWKS 会因 loadPublicKey 失败而整页 500。
     */
    private void retireKeysMissingLocalMaterial() {
        Instant now = Instant.now();
        List<IamSigningKeyEntity> published = signingKeyRepository.findByStatusIn(
                List.of(SigningKeyStatus.ACTIVE, SigningKeyStatus.VERIFYING));
        for (IamSigningKeyEntity entity : published) {
            try {
                secretStore.loadPrivateKey(entity.getKmsKeyId());
            } catch (IamException ex) {
                if (ex.getErrorCode() != IamErrorCode.SIGNING_KEY_NOT_FOUND) {
                    throw ex;
                }
                entity.setStatus(SigningKeyStatus.RETIRED);
                entity.setRetiredAt(now);
                signingKeyRepository.save(entity);
                log.warn(
                        "Retired signing key kid={} after restart; local key material is not persisted",
                        entity.getKid());
            }
        }
    }
}
