package com.example.iam.common.security;

import com.example.iam.common.util.IdGenerator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class CsrfTokenService {

    public static final String COOKIE = "IAM_CSRF";
    public static final String HEADER = "X-CSRF-Token";

    public String read(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (COOKIE.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public String ensure(HttpServletRequest request, HttpServletResponse response) {
        String existing = read(request);
        if (existing != null) {
            writeCookie(request, response, existing);
            return existing;
        }
        String created = IdGenerator.next();
        writeCookie(request, response, created);
        return created;
    }

    public boolean matches(HttpServletRequest request) {
        String cookie = read(request);
        String header = request.getHeader(HEADER);
        return cookie != null && cookie.equals(header);
    }

    private static void writeCookie(HttpServletRequest request, HttpServletResponse response, String value) {
        Cookie cookie = new Cookie(COOKIE, value);
        cookie.setHttpOnly(false);
        cookie.setPath("/");
        cookie.setSecure(request.isSecure());
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }
}
