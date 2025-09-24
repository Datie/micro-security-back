package com.fdkservice.springjwt;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fdkservice.security.models.ERole;
import com.fdkservice.security.models.Role;
import com.fdkservice.security.models.User;
import com.fdkservice.security.security.services.AuthService;

@SpringBootTest
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
	public void delteAllUsers() {
		authService.deleteAllUsers();
		assertTrue(authService.getAllUsers().size() == 0);
	}

}
