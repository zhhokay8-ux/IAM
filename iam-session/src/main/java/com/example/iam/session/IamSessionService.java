package com.example.iam.session;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

public interface IamSessionService {

    IamSession create(String subjectId, String clientId, String authenticationLevel);

    IamSession require(String sid);

    Optional<IamSession> find(String sid);

    /**
     * Loads the Redis payload without enforcing ACTIVE/unexpired. Used by Admin inspection.
     */
    Optional<IamSession> inspect(String sid);

    List<IamSession> listBySubject(String subjectId);

    IamSession touch(String sid);

    void revoke(String sid);

    void revokeAllForSubject(String subjectId);

    void expire(String sid);

    void delete(String sid);

    Duration ttl();

    /**
     * Approximate ACTIVE {@code session:{sid}} count. Uses a 30s Redis cache; never KEYS the whole cluster.
     */
    SessionCount countActive();
}
