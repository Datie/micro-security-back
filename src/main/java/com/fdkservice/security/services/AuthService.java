package com.fdkservice.security.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.fdkservice.security.models.ERole;
import com.fdkservice.security.models.Role;
import com.fdkservice.security.models.User;
import com.fdkservice.security.repository.RoleRepository;
import com.fdkservice.security.repository.UserRepository;

@Service
public class AuthService {
	
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	
	public Role findRoleByName(ERole roleName, String errorMsg) {
		Role userRole = roleRepository.findByName(roleName)
				.orElseThrow(() -> new RuntimeException(errorMsg));
		return userRole;
	}
	
	public User findUserByName(String userName) {
		return userRepository.findByUsername(userName).get();
	}
	
	public boolean existsUserByUsername(String userName) {
		return userRepository.existsByUsername(userName);
	}
	
	public boolean existsUserByEmail(String email) {
		return userRepository.existsByEmail(email);
	}
	
	public List<Role> getAllRoles() {
		return roleRepository.findAll();
	}
	
	@Transactional(propagation = Propagation.REQUIRED)
	public void deleteAllRoles() {
		roleRepository.deleteAll();
	}
	
	@Transactional(propagation = Propagation.REQUIRED)
	public void saveRole(Role role) {
		roleRepository.save(role);
	}
	
	@Transactional(propagation = Propagation.REQUIRED)
	public void deleteUserrolesByUsername(String userName) {
		User user = userRepository.findByUsername(userName).get();
		user.setRoles(null);
		userRepository.save(user);
	}
	
	@Transactional(propagation = Propagation.REQUIRED)
	public void deleteAllUsers() {
		userRepository.deleteAll();
	}
	
	public List<User> getAllUsers() {
		return userRepository.findAll();
	}
	
	@Transactional(propagation = Propagation.REQUIRED)
	public void saveUser(User user) {
		userRepository.save(user);
	}

}
