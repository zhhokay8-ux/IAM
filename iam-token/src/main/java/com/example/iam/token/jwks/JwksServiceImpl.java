package com.example.iam.token.jwks;

import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import com.example.iam.token.signing.SigningKeySecretStore;
import com.example.iam.token.signing.SigningKeyStatus;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class JwksServiceImpl implements JwksService {

    private final IamSigningKeyRepository signingKeyRepository;
    private final SigningKeySecretStore secretStore;

    public JwksServiceImpl(IamSigningKeyRepository signingKeyRepository, SigningKeySecretStore secretStore) {
        this.signingKeyRepository = signingKeyRepository;
        this.secretStore = secretStore;
    }

    @Override
    public JWKSet jwks() {
        List<JWK> keys = signingKeyRepository
                .findByStatusIn(List.of(SigningKeyStatus.ACTIVE, SigningKeyStatus.VERIFYING))
                .stream()
                .map(this::toPublicJwk)
                .toList();
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
