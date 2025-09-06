package com.example.common;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {
    private static final Key ACCESS_KEY = Keys.hmacShaKeyFor("super-secret-access-key-123456789012345".getBytes());
    private static final Key REFRESH_KEY = Keys.hmacShaKeyFor("super-secret-refresh-key-123456789012345".getBytes());

    public static String createAccessToken(String subject, long ttlMillis) {
        return createAccessToken(subject, ttlMillis, null);
    }

    public static String createAccessToken(String subject, long ttlMillis, String[] roles) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date exp = new Date(nowMillis + ttlMillis);

        JwtBuilder b = Jwts.builder()
                .setSubject(subject)
                .claim("typ", "access")
                .setIssuedAt(now)
                .setExpiration(exp);

        if (roles != null) b.claim("roles", roles);

        return b.signWith(ACCESS_KEY, SignatureAlgorithm.HS256).compact();
    }

    public static String createRefreshToken(String subject, long ttlMillis) {
        return createRefreshToken(subject, ttlMillis, null);
    }

    public static String createRefreshToken(String subject, long ttlMillis, String[] roles) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date exp = new Date(nowMillis + ttlMillis);

        JwtBuilder b = Jwts.builder()
                .setSubject(subject)
                .claim("typ", "refresh")
                .setIssuedAt(now)
                .setExpiration(exp);
        if (roles != null) b.claim("roles", roles);

        return b.signWith(REFRESH_KEY, SignatureAlgorithm.HS256).compact();
    }

    public static Jws<Claims> parseAccess(String token) {
        return Jwts.parserBuilder().setSigningKey(ACCESS_KEY).build().parseClaimsJws(token);
    }

    public static Jws<Claims> parseRefresh(String token) {
        return Jwts.parserBuilder().setSigningKey(REFRESH_KEY).build().parseClaimsJws(token);
    }

    public static long getExpirationMillis(String token, boolean refresh) {
        try {
            Claims claims = (refresh ? parseRefresh(token) : parseAccess(token)).getBody();
            return claims.getExpiration().getTime();
        } catch (ExpiredJwtException eje) {
            return eje.getClaims().getExpiration().getTime();
        }
    }
}
