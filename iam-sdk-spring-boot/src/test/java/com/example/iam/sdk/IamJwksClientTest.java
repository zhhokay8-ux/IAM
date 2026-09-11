package com.example.iam.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

class IamJwksClientTest {

    @Test
    void resolvesCachedRsaKeyByKid() {
        SdkTestJwtSupport jwt = new SdkTestJwtSupport();
        IamJwksClient client = IamJwksClient.staticSet(new JWKSet(jwt.rsaJwk()));
        assertEquals(jwt.resolver().resolvePublicKey(SdkTestJwtSupport.KID), client.resolvePublicKey(SdkTestJwtSupport.KID));
        assertEquals("https://auth.example.com/.well-known/jwks.json", client.jwksUri());
    }

    @Test
    void unknownKidFails() {
        SdkTestJwtSupport jwt = new SdkTestJwtSupport();
        IamJwksClient client = IamJwksClient.staticSet(new JWKSet(jwt.rsaJwk()));
        IamException ex = assertThrows(IamException.class, () -> client.resolvePublicKey("missing"));
        assertEquals(IamErrorCode.SIGNING_KEY_NOT_FOUND, ex.getErrorCode());
    }
}
