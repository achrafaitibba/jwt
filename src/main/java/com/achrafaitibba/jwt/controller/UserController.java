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


    //todo use roles and authorization
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
