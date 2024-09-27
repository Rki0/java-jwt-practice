package com.jwtTutorial_yumi.jwtTutorial_yumi.repository;

import com.jwtTutorial_yumi.jwtTutorial_yumi.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
