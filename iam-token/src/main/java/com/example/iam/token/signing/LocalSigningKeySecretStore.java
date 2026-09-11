package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class LocalSigningKeySecretStore implements SigningKeySecretStore {

    private record StoredKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        @Override
        public String toString() {
            return "StoredKey";
        }
    }

    private final ConcurrentHashMap<String, StoredKey> keys = new ConcurrentHashMap<>();

    @Override
    public void store(String kmsKeyId, RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        if (kmsKeyId == null || kmsKeyId.isBlank() || privateKey == null || publicKey == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "signing key material is required");
        }
        keys.put(kmsKeyId, new StoredKey(privateKey, publicKey));
    }

    @Override
    public RSAPrivateKey loadPrivateKey(String kmsKeyId) {
        return require(kmsKeyId).privateKey();
    }

    @Override
    public RSAPublicKey loadPublicKey(String kmsKeyId) {
        return require(kmsKeyId).publicKey();
    }

    @Override
    public void delete(String kmsKeyId) {
        keys.remove(kmsKeyId);
    }

    private StoredKey require(String kmsKeyId) {
        StoredKey stored = keys.get(kmsKeyId);
        if (stored == null) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "signing key material not found");
        }
        return stored;
    }
}
