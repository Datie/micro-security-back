package com.fdkservice.security.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
	
	@Value("${fdkservice.app.jwtSecret}")
    private String jwtSecret;
	
	@Value("${fdkservice.app.tokenType}")
    private String tokenType;

    @Value("${fdkservice.app.jwtExpirationMs}")
    private long jwtExpirationDate;
    
    @Value("${fdkservice.app.jwtDefaultExpirationMs}")
    private long jwtDefaultExpirationMs;
    
    
    public String generateToken(Authentication authentication, boolean rememberMe) {
    	String username = authentication.getName();
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);
        Date defExpireDate = new Date(currentDate.getTime() + jwtDefaultExpirationMs);        
        Date expD = rememberMe?expireDate:defExpireDate;
        String token = Jwts.builder()
        		.header()
        		.type(tokenType)
        		.and()
        		.issuer("SnailClimb")
                .subject(username)
                .issuedAt(new Date())
                .expiration(expD)
                .signWith(key())
                .compact();
        return token;
    }
    
    public String generateToken(String userName, String id, List<String> roles, boolean rememberMe){
        
    	
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);        
        Date defExpireDate = new Date(currentDate.getTime() + jwtDefaultExpirationMs);        
        Date expD = rememberMe?expireDate:defExpireDate;
        String token = Jwts.builder()
        		.header()
        		.type(tokenType)
        		.and()
        		.issuer("SnailClimb")
                .subject(userName)
                .issuedAt(new Date())
                .expiration(expD)
                .id(id)
                .signWith(key())
                .compact();
        return token;
    }
    
    private Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }
    
    public String getUserNameFromJwtToken(String token){
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey)key())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        String username = claims.getSubject();
        return username;
    }
    
    public boolean validateToken(String token){
        try{
            Jwts.parser()
                    .verifyWith((SecretKey)key())
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
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
