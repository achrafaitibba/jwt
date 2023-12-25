package com.achrafaitibba.jwt.configuration.token;

import com.achrafaitibba.jwt.JwtApplication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static java.util.stream.Collectors.toList;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${app.security.jwt.secret-key}")
    private String secretKey;

    @Value("${app.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${app.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    private final TokenRepository tokenRepository;

    //todo 1 > remove hashmap of the others
    /*public String generateToken(UserDetails userDetails){
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "generateToken" + "\n");
        return generateToken(new HashMap<>(),userDetails);
    }*/


    // Takes UserDetails as params, because the main User class implement the UserDetails interface
    // User implements UserDetails = UserDetails
    // Extra claims : to send more data to the client whiting the TOKEN
    // Not only (Username, iat aka initiated at, exp) which are the default claims of the payload
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "generateToken with 2 params" + "\n");
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }
    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "generateRefreshToken" + "\n");
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long expiration
    ) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "buildToken" + "\n");
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Key getSignInKey() {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "getSignInKey" + "\n");

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUsername(String token) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "extractUsername" + "\n");

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "extractClaim with 3 params" + "\n");
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "isTokenValid" + "\n");
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "isTokenExpired" + "\n");
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "extract expiration" + "\n");
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "extractAllClaims" + "\n");

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
    //use it to revoke all previous tokens for a new authentication
    //todo 3 I did move it to here to avoid dependencies circle, previous version takes "user" param
    //todo should it be in userService again ?
    public void revokeAllUserTokens(String userName) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "revokeAllUserTokens" + "\n");

        var validUserTokens = tokenRepository.findAllValidTokensByUser(userName);
        if (validUserTokens.isEmpty())
            return;
        validUserTokens
                .stream()
                .map(t -> {
                    t.setExpired(true);
                    t.setRevoked(true);
                    return t;
                })
                .collect(toList());
        tokenRepository.saveAll(validUserTokens);
    }

}
