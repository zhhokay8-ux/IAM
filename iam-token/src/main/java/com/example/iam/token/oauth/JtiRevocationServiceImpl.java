package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.RevokedJtiRepository;
import java.time.Duration;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

@Service
public class JtiRevocationServiceImpl implements JtiRevocationService {

    private final RevokedJtiRepository repository;

    public JtiRevocationServiceImpl(RevokedJtiRepository repository) {
        this.repository = repository;
    }

    @Override
    public void revoke(String jti) {
        if (jti == null || jti.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "jti is required");
        }
        try {
            repository.revoke(jti);
        } catch (DataAccessException ex) {
            throw unavailable(ex);
        }
    }

    @Override
    public void revoke(String jti, Duration ttl) {
        if (jti == null || jti.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "jti is required");
        }
        try {
            repository.revoke(jti, ttl);
        } catch (DataAccessException ex) {
            throw unavailable(ex);
        }
    }

    @Override
    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        try {
            return repository.isRevoked(jti);
        } catch (DataAccessException ex) {
            throw unavailable(ex);
        }
    }

    private static IamException unavailable(DataAccessException ex) {
        return new IamException(IamErrorCode.INTROSPECTION_UNAVAILABLE, "revocation store is unavailable", ex);
    }
}
