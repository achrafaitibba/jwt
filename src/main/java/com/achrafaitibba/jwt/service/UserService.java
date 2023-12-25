package com.achrafaitibba.jwt.service;

import com.achrafaitibba.jwt.JwtApplication;
import com.achrafaitibba.jwt.configuration.token.JwtService;
import com.achrafaitibba.jwt.configuration.token.Token;
import com.achrafaitibba.jwt.configuration.token.TokenRepository;
import com.achrafaitibba.jwt.configuration.token.TokenType;
import com.achrafaitibba.jwt.dto.UserResponse;
import com.achrafaitibba.jwt.model.User;
import com.achrafaitibba.jwt.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Optional;

import static java.util.stream.Collectors.toList;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;


    public UserResponse register(User user) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "register" + "\n");

        User toSave = userRepository.save(User.builder()
                .username(user.getUsername())
                .password(passwordEncoder.encode(user.getPassword()))
                .build());
        //todo what are the other type of claims we could send to client beside IDs...
        // Instead of initiating an empty hashmap you can create a list of claims and add them to the hashmap
        // Such as birthdate, account status... and any other data needed to be sent to the client whiting the token
        // Example:
        // Map<String, Object> currentDate = new HashMaps<>();
        // currentDate.put("now", LocalDateTime.now()....);
        // Or...
        // Map<String, Object> val = new HashMap<>();
        // val.put("test","test");
        var jwtToken = jwtService.generateToken(new HashMap<>(), toSave);
        var refreshToken = jwtService.generateRefreshToken(toSave);
        saveUserToken(toSave, jwtToken);
        return new UserResponse(user.getUsername(), jwtToken, refreshToken);
    }

    public UserResponse authenticate(User user) {
        Optional<User> toAuthenticate = userRepository.findByUsername(user.getUsername());
        if (!toAuthenticate.isPresent()) {
            System.out.println("Account doesn't exist");
        } else if (!passwordEncoder.matches(user.getPassword(), toAuthenticate.get().getPassword())) {
            System.out.println("The password you entered is incorrect");
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        user.getPassword()
                )
        );
        var jwtToken = jwtService.generateToken(new HashMap<>(), toAuthenticate.get());
        var refreshToken = jwtService.generateRefreshToken(toAuthenticate.get());
        //todo 2, ignore revoking previous tokens in case user is connected in another device
        //revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return new UserResponse(user.getUsername(), jwtToken, refreshToken);

    }


    private void saveUserToken(User user, String jwtToken) {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "saveUserToken" + "\n");
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }



    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response
    ) throws Exception {
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "refreshToken" + "\n");

        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7); // 7 = "Bearer".length + 1 , space
        // extract user email from JWT token; because we set the email as username in the user Model
        username = jwtService.extractUsername(refreshToken);
        if (username != null) {
            var user = this.userRepository.findByUsername(username).orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var newToken = jwtService.generateToken(new HashMap<>(), user);
                jwtService.revokeAllUserTokens(user.getUsername());
                saveUserToken(user, newToken);
                var _response = new UserResponse(username, newToken, refreshToken);
                new ObjectMapper()
                        .writeValue(
                                response.getOutputStream(),
                                _response);
            }
        }
    }


}
