package com.example.resource;

import com.example.common.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            unauthorized(response, "Missing access token");
            return;
        }
        String token = header.substring("Bearer ".length()).trim();
        try {
            Jws<Claims> jws = JwtUtil.parseAccess(token);
            Claims claims = jws.getBody();
            String username = claims.getSubject();
            Collection<SimpleGrantedAuthority> authorities = extractAuthorities(claims);

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            unauthorized(response, "Invalid or expired access token");
        }
    }

    @SuppressWarnings("unchecked")
    private Collection<SimpleGrantedAuthority> extractAuthorities(Claims claims) {
        Object rolesObj = claims.get("roles");
        List<SimpleGrantedAuthority> auths = new ArrayList<>();
        if (rolesObj instanceof List<?> list) {
            for (Object r : list) {
                if (r != null) {
                    auths.add(new SimpleGrantedAuthority(r.toString()));
                }
            }
        }
        return auths;
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("""
                {"code":401,"message":"" + %s + ""}
                """.formatted(message));
    }
}
