package com.example.iam.token.signing;

import java.time.Duration;
import java.util.List;

public interface SigningKeyRotationService {

    KeyMetadata rotate();

    List<KeyMetadata> retireExpired(Duration tokenTtl);
}
