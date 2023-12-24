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

    @PostMapping("/register")
    public UserResponse register(@RequestBody User user){
        JwtApplication.count = 0;
        System.out.println(getClass().getName() + "register" + "\n" + JwtApplication.count++);
        return userService.register(user);
    }


    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    )throws Exception{
        JwtApplication.count = 0;
        System.out.println(getClass().getName() + "register" + "\n" + JwtApplication.count++);
        userService.refreshToken(request, response);
    }

    @GetMapping("/test")

    public String test(){
        JwtApplication.count = 0;
        System.out.println(getClass().getName() + "register" + "\n" + JwtApplication.count++);
        return "You good hh";
    }
}
