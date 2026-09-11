package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SigningKeyServiceImpl implements SigningKeyService {

    static final String ALGORITHM = "RS256";
    private static final Logger log = LoggerFactory.getLogger(SigningKeyServiceImpl.class);

    private final IamSigningKeyRepository signingKeyRepository;
    private final SigningKeySecretStore secretStore;
    private final int rsaKeySize;

    public SigningKeyServiceImpl(
            IamSigningKeyRepository signingKeyRepository,
            SigningKeySecretStore secretStore,
            @Value("${iam.jwt.rsa-key-size:2048}") int rsaKeySize) {
        this.signingKeyRepository = signingKeyRepository;
        this.secretStore = secretStore;
        this.rsaKeySize = rsaKeySize;
    }

    @Override
    @Transactional
    public KeyMetadata createActiveKey() {
        Instant now = Instant.now();
        String kid = newKid(now);
        String kmsKeyId = "local:" + kid;
        KeyPair pair = generateRsaKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        secretStore.store(kmsKeyId, privateKey, publicKey);
        IamSigningKeyEntity saved = signingKeyRepository.save(IamSigningKeyEntity.builder()
                .kid(kid)
                .algorithm(ALGORITHM)
                .kmsKeyId(kmsKeyId)
                .status(SigningKeyStatus.ACTIVE)
                .activatedAt(now)
                .createdAt(now)
                .build());
        log.info("Created signing key kid={} kmsKeyId={}", kid, kmsKeyId);
        return toMetadata(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public KeyMetadata getActiveKey() {
        return signingKeyRepository.findFirstByStatusOrderByActivatedAtDesc(SigningKeyStatus.ACTIVE)
                .map(this::toMetadata)
                .orElseThrow(() -> new IamException(IamErrorCode.NO_ACTIVE_SIGNING_KEY, "no active signing key"));
    }

    @Override
    @Transactional(readOnly = true)
    public KeyMetadata getByKid(String kid) {
        IamSigningKeyEntity entity = signingKeyRepository.findByKid(kid)
                .orElseThrow(() -> new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "unknown kid"));
        return toMetadata(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public List<KeyMetadata> listAll() {
        return signingKeyRepository.findAll().stream()
                .sorted(Comparator.comparing(
                        IamSigningKeyEntity::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .map(this::toMetadata)
                .toList();
    }

    @Override
    public KeyMetadata toMetadata(IamSigningKeyEntity entity) {
        return new KeyMetadata(
                entity.getKid(),
                entity.getAlgorithm(),
                entity.getKmsKeyId(),
                entity.getStatus(),
                entity.getActivatedAt(),
                entity.getRetiredAt(),
                entity.getCreatedAt());
    }

    private KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(rsaKeySize);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "RSA is not available", ex);
        }
    }

    private static String newKid(Instant now) {
        String month = YearMonth.from(now.atZone(ZoneOffset.UTC)).toString().toLowerCase(Locale.ROOT);
        return "iam-key-" + month + "-" + IdGenerator.next().replace("-", "");
    }
}
