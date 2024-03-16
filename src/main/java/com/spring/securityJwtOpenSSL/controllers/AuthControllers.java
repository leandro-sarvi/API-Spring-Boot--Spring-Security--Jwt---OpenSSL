package com.spring.securityJwtOpenSSL.controllers;

import com.spring.securityJwtOpenSSL.persistence.entities.UserEntity;
import com.spring.securityJwtOpenSSL.services.IAuthService;
import com.spring.securityJwtOpenSSL.services.models.dtos.LoginDTO;
import com.spring.securityJwtOpenSSL.services.models.dtos.ResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/auth")
public class AuthControllers {
    private final IAuthService authService;
    public AuthControllers(IAuthService authService){
        this.authService = authService;
    }
    @PostMapping("/login")
    private ResponseEntity<HashMap<String, String>> login(@RequestBody LoginDTO loginRequest) throws Exception {
        HashMap<String,String>  login = authService.login(loginRequest);
        if(login.containsKey("jwt")){
            return ResponseEntity.status(HttpStatus.OK).body(login);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(login);
    }
    @PostMapping("/register")
    private ResponseEntity<ResponseDTO> addUser(@RequestBody UserEntity user) throws Exception {
        return new ResponseEntity<>(authService.register(user), HttpStatus.OK);
    }
}
