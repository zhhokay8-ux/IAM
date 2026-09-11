package com.example.iam.migration;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Locale;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MigrationLoginController {

    public static final String BROWSER_COOKIE = "IAM_MIGRATION_BROWSER";
    public static final String NONCE_COOKIE = "IAM_MIGRATION_NONCE";

    private final MigrationTicketService ticketService;
    private final MigrationClientAuthenticator clientAuthenticator;
    private final IamSessionService sessionService;
    private final MigrationSsoCookieWriter cookieWriter;

    public MigrationLoginController(
            MigrationTicketService ticketService,
            MigrationClientAuthenticator clientAuthenticator,
            IamSessionService sessionService,
            MigrationSsoCookieWriter cookieWriter) {
        this.ticketService = ticketService;
        this.clientAuthenticator = clientAuthenticator;
        this.sessionService = sessionService;
        this.cookieWriter = cookieWriter;
    }

    @PostMapping(path = "/api/migration/ticket", consumes = MediaType.APPLICATION_JSON_VALUE)
    public CreateMigrationTicketResponse issue(
            @RequestBody TicketHttpRequest body, HttpServletRequest httpRequest) {
        rejectForbiddenQuery(httpRequest);
        BasicCredentials basic = parseBasic(httpRequest.getHeader(HttpHeaders.AUTHORIZATION));
        String clientId = firstNonBlank(body.clientId(), basic == null ? null : basic.clientId());
        String secret = firstNonBlank(body.clientSecret(), basic == null ? null : basic.secret());
        clientAuthenticator.authenticateConfidential(clientId, secret);
        return ticketService.issue(new CreateMigrationTicketRequest(
                clientId,
                secret,
                body.systemCode(),
                body.externalUserId(),
                body.subjectId(),
                body.browserSession(),
                body.nonce(),
                body.returnTo()));
    }

    @GetMapping("/migration/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        rejectForbiddenQuery(request);
        String ticket = request.getParameter("ticket");
        MigrationTicketServiceImpl.rejectLegacyInUrl(ticket);
        MigrationTicket redeemed = ticketService.redeem(new RedeemMigrationTicketRequest(
                ticket,
                request.getParameter("client_id"),
                request.getParameter("subject"),
                cookieValue(request, BROWSER_COOKIE),
                cookieValue(request, NONCE_COOKIE)));
        IamSession session = sessionService.create(redeemed.subjectId(), redeemed.clientId(), "migration");
        cookieWriter.write(response, session, sessionService.ttl());
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader(HttpHeaders.LOCATION, redeemed.returnTo());
    }

    static void rejectForbiddenQuery(HttpServletRequest request) {
        Map<String, String[]> params = request.getParameterMap();
        for (String name : params.keySet()) {
            String lower = name.toLowerCase(Locale.ROOT);
            if ("session".equals(lower)
                    || "legacy-session".equals(lower)
                    || "legacy_session".equals(lower)
                    || "access_token".equals(lower)
                    || "id_token".equals(lower)) {
                throw new IamException(
                        IamErrorCode.MIGRATION_LEGACY_IN_URL, "legacy session must not be sent as a query parameter");
            }
            String[] values = params.get(name);
            if (values != null) {
                for (String value : values) {
                    MigrationTicketServiceImpl.rejectLegacyInUrl(value);
                }
            }
        }
    }

    private static String cookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private static String firstNonBlank(String left, String right) {
        if (left != null && !left.isBlank()) {
            return left;
        }
        return right;
    }

    private static BasicCredentials parseBasic(String header) {
        if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        try {
            String decoded = new String(
                    java.util.Base64.getDecoder().decode(header.substring(6).trim()), java.nio.charset.StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 1) {
                return null;
            }
            return new BasicCredentials(decoded.substring(0, colon), decoded.substring(colon + 1));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private record BasicCredentials(String clientId, String secret) {
    }

    public record TicketHttpRequest(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("client_secret") String clientSecret,
            @JsonProperty("system_code") String systemCode,
            @JsonProperty("external_user_id") String externalUserId,
            @JsonProperty("subject_id") String subjectId,
            @JsonProperty("browser_session") String browserSession,
            @JsonProperty("nonce") String nonce,
            @JsonProperty("return_to") String returnTo
    ) {
    }
}
