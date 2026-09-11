package com.example.iam.resourceserver.jwt;

@FunctionalInterface
public interface JtiRevocationStore {

    boolean isRevoked(String jti);
}
