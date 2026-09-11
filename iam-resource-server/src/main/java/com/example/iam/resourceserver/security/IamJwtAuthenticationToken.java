package com.example.iam.resourceserver.security;

import com.example.iam.resourceserver.jwt.ValidatedAccessToken;
import java.util.Collection;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class IamJwtAuthenticationToken extends AbstractAuthenticationToken {

    private final ValidatedAccessToken accessToken;

    public IamJwtAuthenticationToken(ValidatedAccessToken accessToken) {
        super(authorities(accessToken));
        this.accessToken = accessToken;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return accessToken.subject();
    }

    public ValidatedAccessToken accessToken() {
        return accessToken;
    }

    private static Collection<? extends GrantedAuthority> authorities(ValidatedAccessToken token) {
        List<GrantedAuthority> authorities = new java.util.ArrayList<>();
        if (token.scopes() != null) {
            token.scopes().forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));
        }
        if (token.roles() != null) {
            token.roles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }
        return authorities;
    }
}
