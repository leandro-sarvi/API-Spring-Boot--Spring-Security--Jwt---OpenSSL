package com.spring.securityJwtOpenSSL.services.impl;

import com.spring.securityJwtOpenSSL.persistence.entities.UserEntity;
import com.spring.securityJwtOpenSSL.persistence.repositories.UserRepository;
import com.spring.securityJwtOpenSSL.services.IAuthService;
import com.spring.securityJwtOpenSSL.services.IJwtUtilityService;
import com.spring.securityJwtOpenSSL.services.models.dtos.LoginDTO;
import com.spring.securityJwtOpenSSL.services.models.dtos.ResponseDTO;
import com.spring.securityJwtOpenSSL.services.models.validation.UserValidation;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImpl implements IAuthService {
    private UserRepository userRepository;
    private IJwtUtilityService jwtUtilityService;
    private UserValidation userValidation;
    public AuthServiceImpl(UserRepository userRepository,IJwtUtilityService jwtUtilityService,UserValidation userValidation){
        this.userRepository = userRepository;
        this.jwtUtilityService = jwtUtilityService;
        this.userValidation = userValidation;
    }

    @Override
    public HashMap<String, String> login(LoginDTO loginDTO) throws Exception{
        try{
            HashMap<String, String> jwt = new HashMap<>();
            Optional<UserEntity> userEntityOptional = userRepository.findByEmail(loginDTO.getEmail());
            if(userEntityOptional.isEmpty()){
                jwt.put("Error", "User not registered!");
                return jwt;
            }
            //Verificamos contraseña ingresada contra la que esta guardada
            if(verifyPassword(loginDTO.getPassword(),userEntityOptional.get().getPassword())){
                jwt.put("jwt",jwtUtilityService.generateJWT(userEntityOptional.get().getId(),loginDTO.getEmail()));
            }else{
                jwt.put("Error", "Authentication Failed");
                return jwt;
            }
           return jwt;
        }catch (Exception e){
            throw new Exception(e.toString());
        }
    }
    @Override
    public ResponseDTO register(UserEntity user) throws Exception {
        try {
            ResponseDTO response = userValidation.validate(user);
            List<UserEntity> getAllUsers = userRepository.findAll();

            if (response.getNumOfErrors() > 0){
                return response;
            }

            for (UserEntity repeatFields : getAllUsers) {
                if (repeatFields != null) {
                    response.setMessage("User already exists!");
                    return response;
                }
            }

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));
            userRepository.save(user);
            response.setMessage("User created successfully!");
            return response;
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }
    private boolean verifyPassword(String enteredPassword, String storedPassword){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword,storedPassword);
    }
}
