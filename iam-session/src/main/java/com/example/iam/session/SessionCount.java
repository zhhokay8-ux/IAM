package com.example.iam.session;

public record SessionCount(long active, boolean approximate, boolean fromCache) {}
