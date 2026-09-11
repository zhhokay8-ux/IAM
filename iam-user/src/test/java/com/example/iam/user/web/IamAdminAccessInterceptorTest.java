package com.example.iam.user.web;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

class IamAdminAccessInterceptorTest {

    @Test
    void rejectsWhenAdminTokenNotConfigured() throws Exception {
        IamAdminAccessInterceptor interceptor = new IamAdminAccessInterceptor("");
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertFalse(interceptor.preHandle(mock(HttpServletRequest.class), response, new Object()));
        verify(response).sendError(HttpStatus.FORBIDDEN.value(), "Admin API is disabled");
    }

    @Test
    void rejectsInvalidToken() throws Exception {
        IamAdminAccessInterceptor interceptor = new IamAdminAccessInterceptor("secret");
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(IamAdminAccessInterceptor.HEADER)).thenReturn("wrong");
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertFalse(interceptor.preHandle(request, response, new Object()));
        verify(response).sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid admin token");
    }

    @Test
    void allowsMatchingToken() throws Exception {
        IamAdminAccessInterceptor interceptor = new IamAdminAccessInterceptor("secret");
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(IamAdminAccessInterceptor.HEADER)).thenReturn("secret");
        assertTrue(interceptor.preHandle(request, mock(HttpServletResponse.class), new Object()));
    }
}
