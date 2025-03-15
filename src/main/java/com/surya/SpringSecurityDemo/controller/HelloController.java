package com.surya.SpringSecurityDemo.controller;

import com.surya.SpringSecurityDemo.Model.User;
import com.surya.SpringSecurityDemo.service.JwtService;
import com.surya.SpringSecurityDemo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    private UserService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/")
    public String home(){
        return "Hello...";
    }

    @GetMapping("/customer")
    public String getCustomer(HttpServletRequest servletRequest){
        return "User session: " + servletRequest.getSession().getId();
    }

    @PostMapping("/register")
    public String registerUser(@RequestBody User user){
        service.registerUser(user);
        return "User Registered";
    }

    @PostMapping("/login")
    public String userLogin(@RequestBody User user){
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            if (authentication.isAuthenticated())
                return jwtService.getJwtToken(user.getUsername());

        }catch (Exception e){
            return "Failed to login";
        }

        return "Failed to login";

    }
}
