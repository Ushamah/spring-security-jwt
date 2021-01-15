package com.ushwamala.springsecurityjwt.util.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private final String SECRET_KEY = "secret";

    public String extractUserName(String tocken){
        return extractClaim(tocken, Claims::getSubject);
    }

    public Date extractExpiration(String tocken){
        return extractClaim(tocken, Claims::getExpiration);
    }

    public<T> T extractClaim(String tocken, Function<Claims, T> claimsResolver){
        final Claims claims =extractAllClaims(tocken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String tocken) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(tocken).getBody();
    }

    private Boolean isTockeExpired(String tocken){
        return extractExpiration(tocken).before(new Date());
    }

    public String generateTocken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return createTocken(claims,userDetails.getUsername());
    }

    //https://www.baeldung.com/java-json-web-tokens-jjwt
    private String createTocken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * (60*60) * 10))
                .signWith(SignatureAlgorithm.HS256,SECRET_KEY)
                .compact();
    }

    public Boolean validareTocken(String tocken, UserDetails userDetails){
        final String userName = extractUserName(tocken);
        return userName.equals(userDetails.getUsername()) && !isTockeExpired(tocken);
    }

}
