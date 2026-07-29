package org.mvnsearch.security.jwtdemo.jwt;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;

/**
 * JWT authentication filter. Fetch Authorization from http header and inject Authorization into security context
 *
 * @author linux_china
 */
public class JWTAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String authorization = ((HttpServletRequest) request).getHeader("Authorization");
        if (authorization != null) {
            if (authorization.contains("Bearer ")) {
                authorization = authorization.replace("Bearer ", "").trim();
            }
            JwtAuthentication authentication = new JwtAuthentication(authorization);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}