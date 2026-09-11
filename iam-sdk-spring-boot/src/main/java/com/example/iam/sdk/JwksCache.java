package com.example.iam.sdk;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public class JwksCache {

    private final AtomicReference<Entry> value = new AtomicReference<>();

    public Optional<JWKSet> getIfFresh(Instant now) {
        Entry entry = value.get();
        if (entry == null || !entry.expiresAt().isAfter(now)) {
            return Optional.empty();
        }
        return Optional.of(entry.set());
    }

    public Optional<JWKSet> getStale() {
        Entry entry = value.get();
        return entry == null ? Optional.empty() : Optional.of(entry.set());
    }

    public void put(JWKSet set, Instant expiresAt) {
        value.set(new Entry(set, expiresAt));
    }

    private record Entry(JWKSet set, Instant expiresAt) {
    }
}
