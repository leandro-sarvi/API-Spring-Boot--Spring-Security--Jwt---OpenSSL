package com.spring.securityJwtOpenSSL.services;

import com.spring.securityJwtOpenSSL.persistence.entities.UserEntity;
import com.spring.securityJwtOpenSSL.services.models.dtos.LoginDTO;
import com.spring.securityJwtOpenSSL.services.models.dtos.ResponseDTO;

import java.util.HashMap;

public interface IAuthService {
    public HashMap<String, String> login(LoginDTO loginDTO) throws Exception;
    public ResponseDTO register(UserEntity user) throws Exception;
}
