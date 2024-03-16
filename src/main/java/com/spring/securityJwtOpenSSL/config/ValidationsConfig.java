package com.spring.securityJwtOpenSSL.config;

import com.spring.securityJwtOpenSSL.services.models.validation.UserValidation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidationsConfig {
    @Bean
    public UserValidation userValidations(){
        return new UserValidation();
    }
}
