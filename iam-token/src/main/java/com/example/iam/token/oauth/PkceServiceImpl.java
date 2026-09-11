package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.PkceStateRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;
import org.springframework.stereotype.Service;

@Service
public class PkceServiceImpl implements PkceService {

    private static final int MIN_CHALLENGE_LENGTH = 43;
    private static final int MAX_CHALLENGE_LENGTH = 128;

    private final PkceStateRepository pkceStateRepository;

    public PkceServiceImpl(PkceStateRepository pkceStateRepository) {
        this.pkceStateRepository = pkceStateRepository;
    }

    @Override
    public void requireS256(String codeChallengeMethod) {
        if (codeChallengeMethod == null || codeChallengeMethod.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_PKCE, "code_challenge_method is required");
        }
        if (!S256.equals(codeChallengeMethod.trim())) {
            throw new IamException(IamErrorCode.INVALID_PKCE, "code_challenge_method must be S256");
        }
    }

    @Override
    public void requireValidChallenge(String codeChallenge) {
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_PKCE, "code_challenge is required");
        }
        String value = codeChallenge.trim();
        if (value.length() < MIN_CHALLENGE_LENGTH || value.length() > MAX_CHALLENGE_LENGTH) {
            throw new IamException(IamErrorCode.INVALID_PKCE, "code_challenge length is invalid");
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!isUnreserved(ch)) {
                throw new IamException(IamErrorCode.INVALID_PKCE, "code_challenge contains invalid characters");
            }
        }
    }

    @Override
    public String challengeS256(String codeVerifier) {
        requireValidChallenge(codeVerifier);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    @Override
    public boolean matches(String codeVerifier, String codeChallenge) {
        return challengeS256(codeVerifier).equals(codeChallenge);
    }

    @Override
    public void saveChallenge(String state, String codeChallenge) {
        pkceStateRepository.save(state, codeChallenge);
    }

    @Override
    public String requireStoredChallenge(String state) {
        return pkceStateRepository.get(state)
                .orElseThrow(() -> new IamException(IamErrorCode.INVALID_PKCE, "PKCE state not found"));
    }

    private static boolean isUnreserved(char ch) {
        return (ch >= 'A' && ch <= 'Z')
                || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9')
                || ch == '-'
                || ch == '.'
                || ch == '_'
                || ch == '~';
    }

    static boolean isPlain(String method) {
        return method != null && "plain".equals(method.trim().toLowerCase(Locale.ROOT));
    }
}
