package com.hatip.test.repository;

import com.hatip.test.model.entity.UserDetailsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDetailsRepo extends JpaRepository<UserDetailsEntity,Long> {
    public UserDetailsEntity findByUserId(@Param("userId") Long userId);
}
