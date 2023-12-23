package com.achrafaitibba.jwt.configuration.authenticationConfiguration;


import com.achrafaitibba.jwt.JwtApplication;
import com.achrafaitibba.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository accountRepository;



    @Bean
    public UserDetailsService userDetailsService(){
        System.out.println(getClass().getName() + "/" + "UserDetailsService" + "\n" + JwtApplication.count++);
        return username -> accountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        System.out.println(getClass().getName() + "/" + "AuthenticationProvider" + "\n" + JwtApplication.count++);

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)throws Exception{
        System.out.println(getClass().getName() + "/" + "AuthenticationManager" + "\n" + JwtApplication.count++);
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        System.out.println(getClass().getName() + "/" + "PasswordEncoder" + "\n"+ JwtApplication.count++ );


        return new BCryptPasswordEncoder();
    }


}
