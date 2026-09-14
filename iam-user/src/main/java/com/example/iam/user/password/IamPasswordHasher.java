package com.example.iam.user.password;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class IamPasswordHasher {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final String dummyHash = encoder.encode("IAM-DUMMY-PASSWORD-NOT-USED");

    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String storedHash) {
        String candidate = StringUtils.hasText(storedHash) ? storedHash : dummyHash;
        boolean matched = encoder.matches(rawPassword == null ? "" : rawPassword, candidate);
        return StringUtils.hasText(storedHash) && matched;
    }
}
