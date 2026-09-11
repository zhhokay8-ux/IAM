package com.example.iam.token.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtSignerTest {

    private InMemorySigningKeyRepository repository;
    private LocalSigningKeySecretStore secretStore;
    private SigningKeyService signingKeyService;
    private JwtSigner signer;
    private SigningKeyRotationService rotationService;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        secretStore = new LocalSigningKeySecretStore();
        signingKeyService = new SigningKeyServiceImpl(repository, secretStore, 2048);
        JwtKeyResolver resolver = new JwtKeyResolverImpl(repository, secretStore);
        signer = new JwtSignerImpl(signingKeyService, secretStore, resolver);
        rotationService = new SigningKeyRotationServiceImpl(signingKeyService, repository, secretStore);
        signingKeyService.createActiveKey();
    }

    @Test
    void signsWithRs256AtJwtAndKid() throws Exception {
        SignedJWT jwt = signer.sign(claims("u-1"));
        assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
        assertEquals("at+jwt", jwt.getHeader().getType().getType());
        assertEquals(signingKeyService.getActiveKey().kid(), jwt.getHeader().getKeyID());
        SignedJWT verified = signer.verify(jwt.serialize());
        assertEquals("u-1", verified.getJWTClaimsSet().getSubject());
    }

    @Test
    void rejectsInvalidSignature() {
        SignedJWT jwt = signer.sign(claims("u-1"));
        String[] parts = jwt.serialize().split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        IamException ex = assertThrows(IamException.class, () -> signer.verify(tampered));
        assertEquals(IamErrorCode.INVALID_JWT_SIGNATURE, ex.getErrorCode());
    }

    @Test
    void rejectsUnknownKid() {
        JwtKeyResolver resolver = new JwtKeyResolverImpl(repository, secretStore);
        IamException ex = assertThrows(IamException.class, () -> resolver.resolvePublicKey("unknown-kid"));
        assertEquals(IamErrorCode.SIGNING_KEY_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void rejectsRetiredKid() throws Exception {
        SignedJWT signedByOld = signer.sign(claims("old"));
        String oldKid = signedByOld.getHeader().getKeyID();
        rotationService.rotate();
        signer.verify(signedByOld.serialize());
        rotationService.retireExpired(Duration.ZERO);
        IamException ex = assertThrows(IamException.class, () -> signer.verify(signedByOld.serialize()));
        assertEquals(IamErrorCode.SIGNING_KEY_RETIRED, ex.getErrorCode());
        assertEquals(oldKid, signedByOld.getHeader().getKeyID());
    }

    private static JWTClaimsSet claims(String sub) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .subject(sub)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .build();
    }
}
