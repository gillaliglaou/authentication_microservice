package com.Collary.Authentification.system.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // Handle successful authentication and redirect users based on their roles
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // Check if the user has the "manager_admin" role
        boolean isAdmin = authorities.stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_manager_admin"));

        // Check if the user has the "client_employé" role
        boolean isUser = authorities.stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_client_employé"));

        // Redirect to the appropriate page based on the user's role
        if (isAdmin) {
            response.sendRedirect("/admin.html");
        } else if (isUser) {
            response.sendRedirect("/user.html");
        } else {
            response.sendRedirect("/default.html");
        }
    }
}
