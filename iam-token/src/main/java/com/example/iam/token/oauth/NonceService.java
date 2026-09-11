package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.NonceRepository;
import org.springframework.stereotype.Service;

@Service
public class NonceService {

    private static final int MAX_NONCE_LENGTH = 256;

    private final NonceRepository repository;

    public NonceService(NonceRepository repository) {
        this.repository = repository;
    }

    public void requirePresent(String nonce) {
        if (nonce == null || nonce.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "nonce is required");
        }
        if (nonce.length() > MAX_NONCE_LENGTH) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "nonce is too long");
        }
    }

    public void save(String nonce, String context) {
        requirePresent(nonce);
        if (repository.get(nonce).isPresent()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "nonce has already been used");
        }
        repository.save(nonce, context);
    }
}
