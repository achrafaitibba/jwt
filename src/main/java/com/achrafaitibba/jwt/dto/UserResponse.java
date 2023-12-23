package com.achrafaitibba.jwt.dto;

public record UserResponse (
        String username,
        String token,
        String refresh_token

){
}
