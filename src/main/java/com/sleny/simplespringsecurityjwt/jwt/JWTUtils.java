package com.sleny.simplespringsecurityjwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTUtils {

    private static final String AUTHORITIES_KEY = "permissions";
    private static final Logger logger = LoggerFactory.getLogger(JWTUtils.class);
    private static SecretKey secretKey;
    private static int jwtExpirationInMs;

    @Value("${jwt.secret}")
    public void setJwtSecret(String secret){
        secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Value("${jwt.expire}")
    public void setJwtExpirationInMs(int expire){
        jwtExpirationInMs = expire;
    }

    // CreateJWT
    public static String generateToken(Authentication authentication){
        long currentTimeMillis = System.currentTimeMillis();
        Date expirationDate = new Date(currentTimeMillis + jwtExpirationInMs * 1000L);
        String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        Claims claims = Jwts.claims().subject(authentication.getName()).build();
        // 不支持claims.put方法，所以使用.claim()方法
        return Jwts.builder().signWith(secretKey).claims(claims).expiration(expirationDate).claim(AUTHORITIES_KEY, scope).compact();
    }

    // ParseJWT
    public static Authentication getAuthentication(String token){
        Jws<Claims> jws = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        Claims claims = jws.getPayload();
        String permissionString = (String) claims.get("permissions");
        List<SimpleGrantedAuthority> simpleGrantedAuthorityList = permissionString.isBlank() ? new ArrayList<>() : Arrays.stream(permissionString.split(",")).map(SimpleGrantedAuthority::new).toList();
        String username = claims.getSubject();
        return  new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthorityList);
    }

    // Validate JWT Token
    public static boolean validateToken(String token){
        try{
            Jwts.parser().verifyWith(secretKey).build().parse(token);
            return true;
        }catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}

