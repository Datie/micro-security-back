package com.fdkservice.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.fdkservice.security.models.ERole;
import com.fdkservice.security.models.Role;

/**
 * @author Ian
 * @description 
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
