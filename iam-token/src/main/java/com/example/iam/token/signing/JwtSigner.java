package com.example.iam.token.signing;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public interface JwtSigner {

    SignedJWT sign(JWTClaimsSet claims);

    SignedJWT sign(JWTClaimsSet claims, JOSEObjectType type);

    SignedJWT verify(String token);
}
