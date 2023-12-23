package com.achrafaitibba.jwt.configuration.token;

import com.achrafaitibba.jwt.JwtApplication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${app.security.jwt.secret-key}")
    private  String secretKey;

    @Value("${app.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${app.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;



    public String extractUsername(String token) {
        System.out.println(getClass().getName() + "/" + "extractUsername" + "\n" + JwtApplication.count++);

        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        System.out.println(getClass().getName() + "/" + "extractClaim with params" + "\n" + JwtApplication.count++);

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        System.out.println(getClass().getName() + "/" + "generateToken" + "\n" + JwtApplication.count++);
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        System.out.println(getClass().getName() + "/" + "generateToken with params" + "\n" + JwtApplication.count++);
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }
    public String generateRefreshToken(
            UserDetails userDetails
    ){
        System.out.println(getClass().getName() + "/" + "generateRefreshToken" + "\n" + JwtApplication.count++);
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long expiration
                              ){
        System.out.println(getClass().getName() + "/" + "buildToken" + "\n" + JwtApplication.count++);
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        System.out.println(getClass().getName() + "/" + "isTokenValid" + "\n" + JwtApplication.count++);
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        System.out.println(getClass().getName() + "/" + "isTokenExpired" + "\n" + JwtApplication.count++);
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        System.out.println(getClass().getName() + "/" + "extract expiration" + "\n" + JwtApplication.count++);
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        System.out.println(getClass().getName() + "/" + "extractAllClaims" + "\n" + JwtApplication.count++);

        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .parseClaimsJws(token)
                .getBody();
        // or
        // Jwts
//                .parserBuilder()
//                .setSigningKey(getSignInKey())
//                .build()
//                .parseClaimsJwt(token)
//                .getBody();
    }

    private Key getSignInKey() {
        System.out.println(getClass().getName() + "/" + "getSignInKey" + "\n" + JwtApplication.count++);

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
