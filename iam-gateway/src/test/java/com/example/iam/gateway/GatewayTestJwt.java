package com.example.iam.gateway;

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
import java.util.UUID;

final class GatewayTestJwt {

    static final String ISSUER = "https://auth.example.com";
    static final String KID = "gw-kid";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    GatewayTestJwt() {
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
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("at+jwt")).keyID(KID).build(),
                    claims);
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
                .audience("system-n-api")
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", "order.read");
    }
}
