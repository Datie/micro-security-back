package com.fdkservice.springjwt;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fdkservice.security.SpringBootSecurityJwtApplication;
import com.fdkservice.security.models.ERole;
import com.fdkservice.security.models.Role;
import com.fdkservice.security.models.User;
import com.fdkservice.security.services.AuthService;

@SpringBootTest(classes=SpringBootSecurityJwtApplication.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MicroSecurityJwtApplicationTests {
	
	@Autowired
	AuthService authService;
	
	@Autowired
	PasswordEncoder encoder;
	
	void deleteAllUser() {
		authService.deleteAllUsers();
	}
	
	void initRole() {
		authService.deleteAllRoles();
		Role role = new Role();
		role.setName(ERole.ROLE_ADMIN);
		authService.saveRole(role);
		role = new Role();
		role.setName(ERole.ROLE_MODERATOR);
		authService.saveRole(role);
		role = new Role();
		role.setName(ERole.ROLE_USER);
		authService.saveRole(role);
	}

	@Test
	@Order(1) 
	public void contextLoads() {
		deleteAllUser();
		initRole();
		assertTrue(authService.getAllRoles().size() == 3);
	}
	
	@Test
	@Order(2) 
	public void addUser() {
		User user = new User("test1", "aa@aa.com", encoder.encode("123456"));
		Set<Role> roles = new HashSet<>();
		Role role = authService.findRoleByName(ERole.ROLE_USER, "");
		roles.add(role);
		user.setRoles(roles);
		authService.saveUser(user);
		assertTrue(authService.getAllUsers().size() == 1);
	}
	
	@Test
	@Order(3) 
	public void modifyUserRole() {
		User user = authService.findUserByName("test1");
		Role role = authService.findRoleByName(ERole.ROLE_MODERATOR, "");
		Set<Role> roles = user.getRoles();
		roles.add(role);
		//authService.deleteUserrolesByUsername(user.getUsername());
		
		user.setRoles(roles);
		authService.saveUser(user);
		assertTrue(authService.findUserByName("test1").getRoles().size() == 2);
	}
	
	@Test
	@Order(4) 
	public void delteAllUsers() {
		authService.deleteAllUsers();
		assertTrue(authService.getAllUsers().size() == 0);
	}

}
