package com.example.iam.sdk;

import com.example.iam.token.signing.JwtKeyResolver;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

final class SdkTestJwtSupport {

    static final String ISSUER = "https://auth.example.com";
    static final String AUDIENCE = "system-n-api";
    static final String KID = "sdk-test-kid";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    SdkTestJwtSupport() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            this.privateKey = (RSAPrivateKey) pair.getPrivate();
            this.publicKey = (RSAPublicKey) pair.getPublic();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    RSAKey rsaJwk() {
        return new RSAKey.Builder(publicKey).keyID(KID).build();
    }

    JwtKeyResolver resolver() {
        return kid -> {
            if (!KID.equals(kid)) {
                throw new com.example.iam.common.error.IamException(
                        com.example.iam.common.error.IamErrorCode.SIGNING_KEY_NOT_FOUND, "unknown kid");
            }
            return publicKey;
        };
    }

    String token(JWTClaimsSet claims) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("at+jwt"))
                    .keyID(KID)
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("u-100086")
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .jwtID(UUID.randomUUID().toString())
                .claim("client_id", "system-1")
                .claim("scope", "order.read")
                .claim("roles", List.of("order_admin"))
                .claim("tenant_id", "tenant_01")
                .claim("org_id", "org_1001");
    }
}
