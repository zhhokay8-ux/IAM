package com.example.iam.resourceserver.jwt;

import com.example.iam.token.signing.JwtKeyResolver;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
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

public final class TestJwtSupport {

    static final String ISSUER = "https://auth.example.com";
    static final String AUDIENCE = "system-n-api";
    static final String KID = "rs-test-kid";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public TestJwtSupport() {
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

    public JwtKeyResolver resolver() {
        return kid -> {
            if (!KID.equals(kid)) {
                throw new com.example.iam.common.error.IamException(
                        com.example.iam.common.error.IamErrorCode.SIGNING_KEY_NOT_FOUND, "unknown kid");
            }
            return publicKey;
        };
    }

    public String token(JWTClaimsSet claims) {
        return token(claims, KID);
    }

    public String token(JWTClaimsSet claims, String kid) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("at+jwt"))
                    .keyID(kid)
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public JWTClaimsSet.Builder validClaims() {
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
                .claim("scope", "order.read order.query")
                .claim("roles", List.of("order_viewer"))
                .claim("tenant_id", "tenant_01")
                .claim("org_id", "org_1001");
    }
}
