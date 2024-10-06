package com.SpringSecurity.SpringSecurity.service.Impl;

import com.SpringSecurity.SpringSecurity.entities.User;
import com.SpringSecurity.SpringSecurity.service.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTSeviceImpl implements JWTService {

    public String generateToken(UserDetails userDetails){
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public String generateRefreshToken(Map<String,Object> extractClaims,UserDetails userDetails){
        return Jwts.builder().setClaims(extractClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()  // Use parserBuilder() with latest jjwt versions (0.11.0+)
                .setSigningKey(getSignKey())  // Set the signing key for validation
                .build()  // Build the parser
                .parseClaimsJws(token)  // Parse the JWT token
                .getBody();  // Extract the body (claims)
    }

    private Key getSignKey() {
        byte[] key = Decoders.BASE64.decode("4w3JmrUpHeGHxBVkWwA52WGTwQW9d4ThOJX6BERFyCUHwyatkW1KueaR6gGf8luU");
        return Keys.hmacShaKeyFor(key);
    }

    public String extractUserName(String token){
        return extractClaim(token,Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        Date expirationDate = extractClaim(token, Claims::getExpiration); // Extract expiration date from token
        return expirationDate != null && expirationDate.before(new Date()); // Check if the token is expired
    }
}
