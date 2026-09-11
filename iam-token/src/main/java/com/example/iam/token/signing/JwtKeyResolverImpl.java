package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.security.interfaces.RSAPublicKey;
import org.springframework.stereotype.Component;

@Component
public class JwtKeyResolverImpl implements JwtKeyResolver {

    private final IamSigningKeyRepository signingKeyRepository;
    private final SigningKeySecretStore secretStore;

    public JwtKeyResolverImpl(IamSigningKeyRepository signingKeyRepository, SigningKeySecretStore secretStore) {
        this.signingKeyRepository = signingKeyRepository;
        this.secretStore = secretStore;
    }

    @Override
    public RSAPublicKey resolvePublicKey(String kid) {
        if (kid == null || kid.isBlank()) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "kid is required");
        }
        IamSigningKeyEntity entity = signingKeyRepository.findByKid(kid)
                .orElseThrow(() -> new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "unknown kid"));
        if (SigningKeyStatus.RETIRED.equals(entity.getStatus())) {
            throw new IamException(IamErrorCode.SIGNING_KEY_RETIRED, "signing key is retired");
        }
        if (!SigningKeyServiceImpl.ALGORITHM.equals(entity.getAlgorithm())) {
            throw new IamException(IamErrorCode.INVALID_JWT, "unsupported signing algorithm");
        }
        return secretStore.loadPublicKey(entity.getKmsKeyId());
    }
}
