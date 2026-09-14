package com.example.iam.token.jwks;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import com.example.iam.token.signing.SigningKeySecretStore;
import com.example.iam.token.signing.SigningKeyStatus;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class JwksServiceImpl implements JwksService {

    private static final Logger log = LoggerFactory.getLogger(JwksServiceImpl.class);

    private final IamSigningKeyRepository signingKeyRepository;
    private final SigningKeySecretStore secretStore;

    public JwksServiceImpl(IamSigningKeyRepository signingKeyRepository, SigningKeySecretStore secretStore) {
        this.signingKeyRepository = signingKeyRepository;
        this.secretStore = secretStore;
    }

    @Override
    public JWKSet jwks() {
        List<JWK> keys = new ArrayList<>();
        for (IamSigningKeyEntity entity : signingKeyRepository.findByStatusIn(
                List.of(SigningKeyStatus.ACTIVE, SigningKeyStatus.VERIFYING))) {
            try {
                keys.add(toPublicJwk(entity));
            } catch (IamException ex) {
                if (ex.getErrorCode() == IamErrorCode.SIGNING_KEY_NOT_FOUND) {
                    log.warn("Skip JWKS kid={} because signing key material is missing", entity.getKid());
                    continue;
                }
                throw ex;
            }
        }
        return new JWKSet(keys);
    }

    private JWK toPublicJwk(IamSigningKeyEntity entity) {
        RSAKey rsa = new RSAKey.Builder(secretStore.loadPublicKey(entity.getKmsKeyId()))
                .keyID(entity.getKid())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .build();
        return rsa.toPublicJWK();
    }
}
