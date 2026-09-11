package com.example.iam.token.signing;

import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SigningKeyRotationServiceImpl implements SigningKeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyRotationServiceImpl.class);

    private final SigningKeyService signingKeyService;
    private final IamSigningKeyRepository signingKeyRepository;
    private final SigningKeySecretStore secretStore;

    public SigningKeyRotationServiceImpl(
            SigningKeyService signingKeyService,
            IamSigningKeyRepository signingKeyRepository,
            SigningKeySecretStore secretStore) {
        this.signingKeyService = signingKeyService;
        this.signingKeyRepository = signingKeyRepository;
        this.secretStore = secretStore;
    }

    @Override
    @Transactional
    public KeyMetadata rotate() {
        List<IamSigningKeyEntity> currentActive = signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE);
        Instant now = Instant.now();
        for (IamSigningKeyEntity active : currentActive) {
            active.setStatus(SigningKeyStatus.VERIFYING);
            active.setRetiredAt(now);
            signingKeyRepository.save(active);
        }
        KeyMetadata next = signingKeyService.createActiveKey();
        log.info("Rotated signing key to kid={}", next.kid());
        return next;
    }

    @Override
    @Transactional
    public List<KeyMetadata> retireExpired(Duration tokenTtl) {
        Duration ttl = tokenTtl == null ? Duration.ZERO : tokenTtl;
        Instant cutoff = Instant.now().minus(ttl);
        List<KeyMetadata> retired = new ArrayList<>();
        for (IamSigningKeyEntity verifying : signingKeyRepository.findByStatus(SigningKeyStatus.VERIFYING)) {
            Instant retiredAt = verifying.getRetiredAt() == null ? verifying.getActivatedAt() : verifying.getRetiredAt();
            if (retiredAt != null && !retiredAt.isAfter(cutoff)) {
                verifying.setStatus(SigningKeyStatus.RETIRED);
                verifying.setRetiredAt(Instant.now());
                signingKeyRepository.save(verifying);
                secretStore.delete(verifying.getKmsKeyId());
                retired.add(signingKeyService.toMetadata(verifying));
                log.info("Retired signing key kid={}", verifying.getKid());
            }
        }
        return retired;
    }
}
