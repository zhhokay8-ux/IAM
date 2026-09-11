package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class IdTokenServiceImpl implements IdTokenService {

    private final JwtSigner jwtSigner;
    private final String issuer;

    public IdTokenServiceImpl(JwtSigner jwtSigner, @Value("${iam.issuer}") String issuer) {
        this.jwtSigner = jwtSigner;
        this.issuer = issuer;
    }

    @Override
    public String issue(IdTokenClaims claims) {
        Objects.requireNonNull(claims, "claims");
        if (claims.subject() == null || claims.audience() == null || claims.nonce() == null || claims.nonce().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "id token sub, aud, and nonce are required");
        }
        JWTClaimsSet jwt = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(claims.subject())
                .audience(claims.audience())
                .issueTime(Date.from(claims.issuedAt()))
                .expirationTime(Date.from(claims.expiresAt()))
                .claim("nonce", claims.nonce())
                .build();
        return jwtSigner.sign(jwt, JOSEObjectType.JWT).serialize();
    }
}
