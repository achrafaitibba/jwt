package com.achrafaitibba.jwt.configuration.authenticationConfiguration;

import com.achrafaitibba.jwt.JwtApplication;
import com.achrafaitibba.jwt.configuration.token.JwtService;
import com.achrafaitibba.jwt.configuration.token.TokenRepository;
import com.achrafaitibba.jwt.repository.UserRepository;
import com.achrafaitibba.jwt.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository ITokenRepository;
    private final JwtService jwtService;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/  logout" + "\n" );

        final String authHeader = request.getHeader("Authorization");
        final String logout = request.getHeader("Mode");
        final String jwt;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        jwt = authHeader.substring(7);
        if(logout.toUpperCase().equals(LogoutMode.ALL_DEVICES.getMode())){
            String username = jwtService.extractUsername(jwt);
            jwtService.revokeAllUserTokens(username);
        }else if(logout.toUpperCase().equals(LogoutMode.Current_Device.getMode())){
            var storedToken = ITokenRepository.findByToken(jwt)
                    .orElse(null);
            if(storedToken != null){
                storedToken.setExpired(true);
                storedToken.setRevoked(true);
                ITokenRepository.save(storedToken);
            }
        }
    }
}
