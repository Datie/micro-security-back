package com.fdkservice.security.security.jwt;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Ian
 * @description AccessDeineHandler To handle the exception when the user authorized visits the resource which is not for the user
 */
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    /**
     * send 403 and error messages when user visits the REST resources which are not for the user
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        accessDeniedException = new AccessDeniedException("Sorry you don not enough permissions to access it!");
        response.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
    }
}
