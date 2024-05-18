package com.dto.way.gateway.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import javax.crypto.SecretKey;

@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;


    // application.yml에서 secret 값 가져와서 key에 저장
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtTokenValidationResult validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return new JwtTokenValidationResult(true, "Valid JWT Token"); // 토큰 유효성 검사 성공
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
            return new JwtTokenValidationResult(false, "Invalid JWT Token");
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            return new JwtTokenValidationResult(false, "Expired JWT Token");
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
            return new JwtTokenValidationResult(false, "Unsupported JWT Token");
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
            return new JwtTokenValidationResult(false, "JWT claims string is empty.");
        }
    }

}

