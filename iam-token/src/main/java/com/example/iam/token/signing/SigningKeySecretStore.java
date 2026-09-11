package com.example.iam.token.signing;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface SigningKeySecretStore {

    void store(String kmsKeyId, RSAPrivateKey privateKey, RSAPublicKey publicKey);

    RSAPrivateKey loadPrivateKey(String kmsKeyId);

    RSAPublicKey loadPublicKey(String kmsKeyId);

    void delete(String kmsKeyId);
}
