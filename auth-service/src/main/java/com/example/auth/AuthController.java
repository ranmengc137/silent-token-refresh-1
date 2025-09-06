package com.example.auth;

import com.example.common.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final long ACCESS_TTL = 20_000L;
    private static final long REFRESH_TTL = 5 * 60_000L;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> payload) {
        String user = payload.getOrDefault("username", "guest");
        String[] roles = new String[] {"ROLE_USER"}; // demo role
        String access = JwtUtil.createAccessToken(user, ACCESS_TTL, roles);
        String refresh = JwtUtil.createRefreshToken(user, REFRESH_TTL, roles);

        Map<String, Object> res = new HashMap<>();
        res.put("token", access);
        res.put("tokenExpire", JwtUtil.getExpirationMillis(access, false));
        res.put("refreshToken", refresh);
        res.put("refreshExpire", JwtUtil.getExpirationMillis(refresh, true));
        return ResponseEntity.ok(res);
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestHeader("Authorization") String authHeader) {
        String token = extractBearer(authHeader);
        try {
            Jws<Claims> claims = JwtUtil.parseRefresh(token);
            String user = claims.getBody().getSubject();
            List rolesList = (List) claims.getBody().get("roles");
            String[] roles = null;
            if (rolesList != null) {
                roles = (String[]) rolesList.stream().map(Object::toString).toArray(String[]::new);
            }
            String access = JwtUtil.createAccessToken(user, ACCESS_TTL, roles);

            Map<String, Object> res = new HashMap<>();
            res.put("token", access);
            res.put("tokenExpire", JwtUtil.getExpirationMillis(access, false));
            return ResponseEntity.ok(res);
        } catch (ExpiredJwtException eje) {
            return ResponseEntity.status(401).body(Map.of("code", 401, "message", "Refresh token expired"));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("code", 401, "message", "Invalid refresh token"));
        }
    }

    private String extractBearer(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Missing Bearer token");
        }
        return header.substring("Bearer ".length()).trim();
    }
}
