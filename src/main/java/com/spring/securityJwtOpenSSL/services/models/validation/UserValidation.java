package com.spring.securityJwtOpenSSL.services.models.validation;

import com.spring.securityJwtOpenSSL.persistence.entities.UserEntity;
import com.spring.securityJwtOpenSSL.services.models.dtos.ResponseDTO;

public class UserValidation {
    public ResponseDTO validate(UserEntity user){
        ResponseDTO response = new ResponseDTO();

        response.setNumOfErrors(0);

        if (user.getUsername() == null || user.getUsername().length() < 3 || user.getUsername().length() > 15){
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            response.setMessage("El campo firstName no puede ser nulo, tampoco puede tener menos de 3 caracteres ni mas de 15");
        }

        if (
                user.getEmail() == null ||
                        !user.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")
        ){
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            response.setMessage("El campo email no es correcto");
        }

        if(
                user.getPassword() == null ||
                        !user.getPassword().matches("^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,16}$")
        ){
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            response.setMessage("La contraseña debe tener entre 8 y 16 caracteres, al menos un número, una minúscula y una mayúscula.");
        }

        return response;
    }
}
