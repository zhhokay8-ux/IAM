package com.example.iam.token.signing;

import java.security.interfaces.RSAPublicKey;

public interface JwtKeyResolver {

    RSAPublicKey resolvePublicKey(String kid);
}
