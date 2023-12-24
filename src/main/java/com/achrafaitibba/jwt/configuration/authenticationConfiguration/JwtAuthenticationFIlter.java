package com.achrafaitibba.jwt.configuration.authenticationConfiguration;


import com.achrafaitibba.jwt.JwtApplication;
import com.achrafaitibba.jwt.configuration.token.JwtService;
import com.achrafaitibba.jwt.configuration.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFIlter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository ITokenRepository;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "doFilterInternal" + "\n");
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            // It will go to the next filter in the filterChain, because all filters are chained (Invoke the next filter)
            // The last element of the chain is the target resource/servlet.
            filterChain.doFilter(request, response);
            return ; // empty return: means the program will not execute the rest of the code
        }
        jwt = authHeader.substring(7); // 7 = "Bearer".length + 1 , space
        // extract username
        // "could be email/ID or any attribute set to be username in UserDetails instance" from JWT token;
        // in this case I set username in the user Model
        username = jwtService.extractUsername(jwt);
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
             var isTokenValid = ITokenRepository.findByToken(jwt)
                     .map(t -> !t.isExpired() && !t.isRevoked())
                     .orElse(false);
            if(jwtService.isTokenValid(jwt, userDetails) && isTokenValid){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
