package com.achrafaitibba.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtApplication {
    public static int count;

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

}
