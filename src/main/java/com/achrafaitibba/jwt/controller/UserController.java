package com.achrafaitibba.jwt.controller;

import com.achrafaitibba.jwt.JwtApplication;
import com.achrafaitibba.jwt.dto.UserResponse;
import com.achrafaitibba.jwt.model.User;
import com.achrafaitibba.jwt.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor

public class UserController {
    private final UserService userService;

    //todo authenticate
    //todo revoke all tokens
    //todo use roles and authorization
    //todo authenticate should not revoke previous tokens, to keep account opened in other devices;
    //todo logout should have two options "logout from this device, logout from all devices"
    @PostMapping("/register")
    public UserResponse register(@RequestBody User user){
        JwtApplication.count = 1;
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "register" + "\n");
        return userService.register(user);
    }

    @PostMapping("/authenticate")
    public UserResponse authenticate(@RequestBody User user){
        JwtApplication.count = 1;
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "authenticate" + "\n");
        return userService.authenticate(user);
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    )throws Exception{
        JwtApplication.count = 1;
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "register" + "\n");
        userService.refreshToken(request, response);
    }

    @GetMapping("/test")

    public String test(){
        JwtApplication.count = 1;
        System.out.println(JwtApplication.count++ + "/ " + getClass().getName() + "register" + "\n");
        return "You good hh";
    }
}
