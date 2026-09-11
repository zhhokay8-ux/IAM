package com.example.iam.authorizationserver.oidc.logout;

import com.example.iam.session.IamSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface LogoutService {

    void logout(HttpServletRequest request, HttpServletResponse response, String logoutType);

    void localLogout(HttpServletResponse response);

    void globalLogout(IamSession session, HttpServletResponse response);
}
