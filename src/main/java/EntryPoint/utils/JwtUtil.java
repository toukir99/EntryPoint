package EntryPoint.utils;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import EntryPoint.exception.GlobalExceptionHandler.ExpiredJwtException;

@Component
public class JwtUtil {
    private final String secretKey;
    private final Set<String> invalidatedTokens = new HashSet<>();  // In-memory blacklist

    public JwtUtil(@Value("${access.token}") String secretKey) {
        this.secretKey = secretKey;
    }

    private SecretKey getSigningKey() {
        return new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    }

    long now = System.currentTimeMillis();
    int accessTokenExpiration = 1000 * 60 * 5;
    int refreshTokenExpiration = 1000 * 60 * 60;

    public String generateAccessToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(now)) // Set issued at time
                .setExpiration(new Date(now + accessTokenExpiration)) // 5 minutes expiration
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(now)) // Set issued at time
                .setExpiration(new Date(now + refreshTokenExpiration)) // 1 hour expiration
                .signWith(getSigningKey())
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("Invalid JWT signature or malformed token");
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("Unsupported JWT token");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT claims string is empty");
        }
    }

    public String extractEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public void invalidateToken(String token) {
        invalidatedTokens.add(token);
    }

    public boolean isTokenInvalidated(String token) {
        return invalidatedTokens.contains(token);
    }

    public String extractToken(String tokenHeader) {
        return tokenHeader.substring(7).trim();
    }
}

