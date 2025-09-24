package com.fdkservice.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.fdkservice.security.models.User;

/**
 * @author Ian
 * @description 
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);
	
	void deleteByUsername(String userName);

	Boolean existsByUsername(String username);

	Boolean existsByEmail(String email);
}
