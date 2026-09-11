package com.example.iam.authorizationserver.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record OidcDiscoveryResponse(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
        @JsonProperty("revocation_endpoint") String revocationEndpoint,
        @JsonProperty("introspection_endpoint") String introspectionEndpoint,
        @JsonProperty("end_session_endpoint") String endSessionEndpoint,
        @JsonProperty("backchannel_logout_endpoint") String backchannelLogoutEndpoint,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("claims_supported") List<String> claimsSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported
) {
}
