package com.spring.securityJwtOpenSSL.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.spring.securityJwtOpenSSL.services.models.dtos.LoginDTO;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

public interface IJwtUtilityService {
    public String generateJWT(Long id, String email) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException;
    public JWTClaimsSet parseJWT(String jwt) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ParseException, JOSEException;
}
