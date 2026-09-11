package com.example.iam.authorizationserver.sso;

import com.example.iam.session.IamSession;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.stereotype.Service;

@Service
public class SsoCookieService {

    public static final String COOKIE_NAME = "IAM_SSO_SESSION";

    private final IamSsoProperties properties;

    public SsoCookieService(IamSsoProperties properties) {
        this.properties = properties;
    }

    public String cookieName() {
        String configured = properties.getCookieName();
        return configured == null || configured.isBlank() ? COOKIE_NAME : configured;
    }

    public void write(HttpServletResponse response, IamSession session, Duration maxAge) {
        addCookie(response, session.sid(), maxAge);
    }

    public void clear(HttpServletResponse response) {
        addCookie(response, "", Duration.ZERO);
    }

    public String readSid(HttpServletRequest request) {
        if (request == null || request.getCookies() == null) {
            return null;
        }
        String name = cookieName();
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void addCookie(HttpServletResponse response, String value, Duration maxAge) {
        Cookie cookie = new Cookie(cookieName(), value == null ? "" : value);
        cookie.setHttpOnly(true);
        cookie.setSecure(properties.isCookieSecure());
        cookie.setPath(properties.getCookiePath() == null || properties.getCookiePath().isBlank()
                ? "/"
                : properties.getCookiePath());
        long seconds = maxAge == null ? 0 : maxAge.toSeconds();
        if (seconds > Integer.MAX_VALUE) {
            seconds = Integer.MAX_VALUE;
        }
        cookie.setMaxAge((int) Math.max(0, seconds));
        String sameSite = properties.getCookieSameSite() == null || properties.getCookieSameSite().isBlank()
                ? "Lax"
                : properties.getCookieSameSite();
        cookie.setAttribute("SameSite", sameSite);
        response.addCookie(cookie);
    }
}
