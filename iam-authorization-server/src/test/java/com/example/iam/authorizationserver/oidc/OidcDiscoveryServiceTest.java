package com.example.iam.authorizationserver.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamException;
import org.junit.jupiter.api.Test;

class OidcDiscoveryServiceTest {

    @Test
    void buildsEndpointsFromConfiguredIssuerWithoutHardcodedDomain() {
        OidcDiscoveryService service = new OidcDiscoveryService("https://iam.internal.test");
        OidcDiscoveryResponse document = service.discovery();
        assertEquals("https://iam.internal.test", document.issuer());
        assertEquals("https://iam.internal.test/oauth2/token", document.tokenEndpoint());
        assertEquals("https://iam.internal.test/.well-known/jwks.json", document.jwksUri());
        assertTrue(document.grantTypesSupported().contains(OidcDiscoveryService.GRANT_TOKEN_EXCHANGE));
        assertTrue(document.codeChallengeMethodsSupported().contains(OidcDiscoveryService.PKCE_S256));
    }

    @Test
    void stripsTrailingSlashAndRejectsUserinfo() {
        OidcDiscoveryService service = new OidcDiscoveryService("https://iam.internal.test/");
        assertEquals("https://iam.internal.test", service.issuer());
        assertThrows(IamException.class, () -> new OidcDiscoveryService("https://user:pass@iam.internal.test"));
    }

    @Test
    void rejectsInsecureNonLocalIssuer() {
        assertThrows(IamException.class, () -> new OidcDiscoveryService("http://evil.example.com"));
    }
}
