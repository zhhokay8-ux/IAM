package com.example.iam.token.signing;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import org.springframework.stereotype.Component;

@Component
public class JwtSignerImpl implements JwtSigner {

    static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    private final SigningKeyService signingKeyService;
    private final SigningKeySecretStore secretStore;
    private final JwtKeyResolver keyResolver;

    public JwtSignerImpl(
            SigningKeyService signingKeyService,
            SigningKeySecretStore secretStore,
            JwtKeyResolver keyResolver) {
        this.signingKeyService = signingKeyService;
        this.secretStore = secretStore;
        this.keyResolver = keyResolver;
    }

    @Override
    public SignedJWT sign(JWTClaimsSet claims) {
        return sign(claims, ACCESS_TOKEN_TYPE);
    }

    @Override
    public SignedJWT sign(JWTClaimsSet claims, JOSEObjectType type) {
        KeyMetadata active = signingKeyService.getActiveKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(type == null ? ACCESS_TOKEN_TYPE : type)
                .keyID(active.kid())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(secretStore.loadPrivateKey(active.kmsKeyId())));
            return jwt;
        } catch (JOSEException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "failed to sign JWT", ex);
        }
    }

    @Override
    public SignedJWT verify(String token) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT is malformed", ex);
        }
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT alg must be RS256");
        }
        RSAPublicKey publicKey = keyResolver.resolvePublicKey(jwt.getHeader().getKeyID());
        try {
            if (!jwt.verify(new RSASSAVerifier(publicKey))) {
                throw new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "JWT signature is invalid");
            }
            return jwt;
        } catch (JOSEException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "JWT signature is invalid", ex);
        }
    }
}
