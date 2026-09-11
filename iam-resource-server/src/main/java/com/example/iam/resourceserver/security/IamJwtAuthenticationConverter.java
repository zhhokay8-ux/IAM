package com.example.iam.resourceserver.security;

import com.example.iam.resourceserver.jwt.JwtTokenValidator;
import com.example.iam.resourceserver.jwt.ValidatedAccessToken;

public class IamJwtAuthenticationConverter {

    private final JwtTokenValidator validator;

    public IamJwtAuthenticationConverter(JwtTokenValidator validator) {
        this.validator = validator;
    }

    public IamJwtAuthenticationToken convert(String bearerToken) {
        ValidatedAccessToken accessToken = validator.validate(bearerToken);
        return new IamJwtAuthenticationToken(accessToken);
    }
}
