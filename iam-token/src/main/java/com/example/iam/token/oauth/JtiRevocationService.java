package com.example.iam.token.oauth;

import java.time.Duration;

public interface JtiRevocationService {

    void revoke(String jti);

    void revoke(String jti, Duration ttl);

    boolean isRevoked(String jti);
}
