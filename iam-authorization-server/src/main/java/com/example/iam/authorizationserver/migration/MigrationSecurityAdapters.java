package com.example.iam.authorizationserver.migration;

import com.example.iam.authorizationserver.oauth.token.ClientAuthenticationProvider;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.migration.MigrationClientAuthenticator;
import com.example.iam.migration.MigrationSsoCookieWriter;
import com.example.iam.session.IamSession;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.stereotype.Component;

@Component
public class MigrationSecurityAdapters implements MigrationClientAuthenticator, MigrationSsoCookieWriter {

    private final ClientAuthenticationProvider clientAuthenticationProvider;
    private final SsoCookieService cookieService;

    public MigrationSecurityAdapters(
            ClientAuthenticationProvider clientAuthenticationProvider, SsoCookieService cookieService) {
        this.clientAuthenticationProvider = clientAuthenticationProvider;
        this.cookieService = cookieService;
    }

    @Override
    public void authenticateConfidential(String clientId, String clientSecret) {
        clientAuthenticationProvider.authenticateConfidential(clientId, clientSecret);
    }

    @Override
    public void write(HttpServletResponse response, IamSession session, Duration ttl) {
        cookieService.write(response, session, ttl);
    }
}
