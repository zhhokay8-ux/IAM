package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;
import java.time.Instant;
import java.util.List;

public interface ServiceTokenService {

    String SUBJECT_PREFIX = "client:";
    String TOKEN_USE = "service";

    String issue(IamClientEntity client, List<String> audiences, String scope);

    String issue(IamClientEntity client, List<String> audiences, String scope, Instant issuedAt);

    static String subjectFor(String clientId) {
        return SUBJECT_PREFIX + clientId;
    }

    static boolean isServiceSubject(String subject) {
        return subject != null && subject.startsWith(SUBJECT_PREFIX);
    }
}
