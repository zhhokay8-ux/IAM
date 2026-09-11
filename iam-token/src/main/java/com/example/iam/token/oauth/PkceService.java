package com.example.iam.token.oauth;

public interface PkceService {

    String S256 = "S256";

    void requireS256(String codeChallengeMethod);

    void requireValidChallenge(String codeChallenge);

    String challengeS256(String codeVerifier);

    boolean matches(String codeVerifier, String codeChallenge);

    void saveChallenge(String state, String codeChallenge);

    String requireStoredChallenge(String state);
}
