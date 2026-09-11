package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenServiceImpl implements AccessTokenService {

    private final JwtSigner jwtSigner;
    private final String issuer;

    public AccessTokenServiceImpl(JwtSigner jwtSigner, @Value("${iam.issuer}") String issuer) {
        this.jwtSigner = jwtSigner;
        this.issuer = issuer;
    }

    @Override
    public String issue(AccessTokenClaims claims) {
        Objects.requireNonNull(claims, "claims");
        if (claims.subject() == null || claims.audiences() == null || claims.audiences().isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "access token subject and audience are required");
        }
        String jti = claims.jti() == null ? IdGenerator.next() : claims.jti();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(claims.subject())
                .audience(claims.audiences())
                .issueTime(Date.from(claims.issuedAt()))
                .notBeforeTime(Date.from(claims.issuedAt()))
                .expirationTime(Date.from(claims.expiresAt()))
                .jwtID(jti)
                .claim("client_id", claims.clientId())
                .claim("scope", claims.scope());
        if (claims.roles() != null && !claims.roles().isEmpty()) {
            builder.claim("roles", claims.roles());
        }
        if (claims.tenantId() != null && !claims.tenantId().isBlank()) {
            builder.claim("tenant_id", claims.tenantId());
        }
        if (claims.orgId() != null && !claims.orgId().isBlank()) {
            builder.claim("org_id", claims.orgId());
        }
        if (claims.actSub() != null && !claims.actSub().isBlank()) {
            builder.claim("act", java.util.Map.of("sub", claims.actSub()));
        }
        if (claims.tokenUse() != null && !claims.tokenUse().isBlank()) {
            builder.claim("token_use", claims.tokenUse());
        }
        return jwtSigner.sign(builder.build()).serialize();
    }
}
