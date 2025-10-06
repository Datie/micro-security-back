package com.fdkservice.security.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fdkservice.security.models.ERole;
import com.fdkservice.security.models.Role;
import com.fdkservice.security.models.User;
import com.fdkservice.security.payload.request.LoginRequest;
import com.fdkservice.security.payload.request.SignupRequest;
import com.fdkservice.security.payload.response.JwtResponse;
import com.fdkservice.security.payload.response.MessageResponse;
import com.fdkservice.security.security.jwt.JwtTokenProvider;
import com.fdkservice.security.services.AuthService;
import com.fdkservice.security.services.UserDetailsImpl;

import jakarta.validation.Valid;

/**
 * @author Ian
 * @description Controller for login and signup
 */

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	AuthService authService;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtTokenProvider jwtTokenProvider;
	
	@Autowired
	MessageSource messageSource;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = null;
		try {
			authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		} catch(RuntimeException e) {
			return ResponseEntity.badRequest().body(new MessageResponse(messageSource.getMessage("LOGIN_WRONG", null, null, null)));
		}
		if(authentication.isAuthenticated()) {
			System.out.println("---------------authenticated");
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			String jwt = jwtTokenProvider.generateToken(authentication, false);
			
			UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
			List<String> roles = userDetails.getAuthorities().stream()
					.map(item -> item.getAuthority())
					.collect(Collectors.toList());

			return ResponseEntity.ok(new JwtResponse(jwt, 
													 userDetails.getId(), 
													 userDetails.getUsername(), 
													 userDetails.getEmail(), 
													 roles));
		} else {
			System.out.println("---------------not authenticated");
			return ResponseEntity.badRequest().body(new MessageResponse(messageSource.getMessage("LOGIN_WRONG", null, null, null)));
		}
		
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (authService.existsUserByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse(messageSource.getMessage("USER_EXIST", null, null, null)));
		}

		if (authService.existsUserByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse(messageSource.getMessage("EMAIL_USED", null, null, null)));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = authService.findRoleByName(ERole.ROLE_USER, messageSource.getMessage("ROLE_NOT_FOUND", null, null, null));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = authService.findRoleByName(ERole.ROLE_ADMIN, messageSource.getMessage("ROLE_NOT_FOUND", null, null, null));
					roles.add(adminRole);
					break;
				case "mod":
					Role modRole = authService.findRoleByName(ERole.ROLE_MODERATOR, messageSource.getMessage("ROLE_NOT_FOUND", null, null, null));
					roles.add(modRole);
					break;
				default:
					Role userRole = authService.findRoleByName(ERole.ROLE_USER, messageSource.getMessage("ROLE_NOT_FOUND", null, null, null));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		authService.saveUser(user);
		return ResponseEntity.ok(new MessageResponse(messageSource.getMessage("USER_CREATE_SUCCESS", null, null, null)));
	}
}
