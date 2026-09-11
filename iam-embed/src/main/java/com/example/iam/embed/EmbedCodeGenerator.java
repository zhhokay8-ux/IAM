package com.example.iam.embed;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public class EmbedCodeGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    public String next() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return "EC_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
