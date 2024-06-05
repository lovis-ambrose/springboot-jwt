package com.security.JWT.service;

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
public class JwtService {
    private static final String SECRET_KEY = "e99cc357380d0345fff0505e3b1f89b04c498bfc66f848cbd8f8fe8239df19794169b1ebb43f8fff85dee1610e70e4f27da1d855d4f074a38f9e1db4e930a012";
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);//get subject means get email of user
    }

    //generic method to extract a single claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsTFunction){
        final Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    //generate token without extraClaims ie just from UserDetails itself
    public String extractToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    //extraClaims used to passing any extra info e.g. authorities that you need to store within the token
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // valid for 24hrs + 1000 milliseconds
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); //will build and return token
    }

    //method to validate token ie if token belongs to user details
    //return username if token belongs to user details and token is not expired
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
