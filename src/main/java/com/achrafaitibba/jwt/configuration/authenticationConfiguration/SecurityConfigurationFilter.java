package com.achrafaitibba.jwt.configuration.authenticationConfiguration;



import com.achrafaitibba.jwt.JwtApplication;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurationFilter {

    private final JwtAuthenticationFIlter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutService logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception{
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "/" + "SecurityFilterChain" + "\n");


        httpSecurity
                .csrf()
                .disable()
                .cors() // to allow cors from all origins
                .and()
                .authorizeHttpRequests()
                .requestMatchers(
                        "/api/register",
                        "/api/refresh-token",
                        "/api/authenticate"
                )
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //enable frames, I used it for swagger documentation to put it inside an IFRAME tag
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(
                        (request,
                         response,
                         authentication) ->
                        SecurityContextHolder.clearContext())
        ;
        return httpSecurity.build();
    }
}
