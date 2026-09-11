package com.example.iam.token.jwks;

import com.nimbusds.jose.jwk.JWKSet;

public interface JwksService {

    JWKSet jwks();
}
