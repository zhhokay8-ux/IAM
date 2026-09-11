package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.OAuthStateRepository;
import org.springframework.stereotype.Service;

@Service
public class OAuthStateService {

    private static final int MAX_STATE_LENGTH = 256;

    private final OAuthStateRepository repository;

    public OAuthStateService(OAuthStateRepository repository) {
        this.repository = repository;
    }

    public void requirePresent(String state) {
        if (state == null || state.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "state is required");
        }
        if (state.length() > MAX_STATE_LENGTH) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "state is too long");
        }
    }

    public void save(String state, String clientId) {
        requirePresent(state);
        repository.save(state, clientId);
    }
}
