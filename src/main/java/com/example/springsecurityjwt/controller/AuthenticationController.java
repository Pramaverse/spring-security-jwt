package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.LoginResponseDTO;
import com.example.springsecurityjwt.dto.RegistrationDTO;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.service.AuthenticationService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthenticationController {

    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public User registerUser(@RequestBody RegistrationDTO regDtoObj) {
        return authenticationService.registerUser(regDtoObj.getUsername(), regDtoObj.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTO returnToken(@RequestBody RegistrationDTO regDtoObj) {
        return authenticationService.logInUser(regDtoObj.getUsername(), regDtoObj.getPassword());
    }
}
