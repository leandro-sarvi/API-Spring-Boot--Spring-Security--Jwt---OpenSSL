package com.spring.securityJwtOpenSSL.controllers;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/prueba")
public class PruebaControllers {
    @GetMapping("/message")
    public ResponseEntity<String> getMessage(){
        return ResponseEntity.status(HttpStatus.OK).body("Prueba Ok");
    }
}
