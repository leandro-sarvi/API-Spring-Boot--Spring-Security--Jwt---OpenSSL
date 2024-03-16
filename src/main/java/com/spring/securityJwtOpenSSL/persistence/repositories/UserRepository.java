package com.spring.securityJwtOpenSSL.persistence.repositories;

import com.spring.securityJwtOpenSSL.persistence.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    @Query(value = "SELECT * FROM _user WHERE email = :email",nativeQuery = true)
    Optional<UserEntity> findByEmail(String email);
}
