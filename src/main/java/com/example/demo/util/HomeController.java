package com.example.demo.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.JwtRequest;
import com.example.demo.model.JwtResponse;
import com.example.demo.service.MyUserDetailsService;

@RestController
public class HomeController {
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	MyUserDetailsService myUserDetailsService;
	
	@Autowired
	Utility jwtUtility;

	@GetMapping("/")
	public String home() {
		return "Welcome to my home";
	}
	
	@PostMapping("/authenticate")
	public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {

	    try{
	        authenticationManager.authenticate(
	                new UsernamePasswordAuthenticationToken(
	                        jwtRequest.getUsername(),
	                        jwtRequest.getPassword()
	                )
	        );
	    } catch (BadCredentialsException e) {
	        throw new Exception("Invalid Credentials", e);
	    }

	    final UserDetails userDetails
	            = myUserDetailsService.loadUserByUsername(jwtRequest.getUsername());

	    final String token =
	            jwtUtility.generateToken(userDetails);

	    return new JwtResponse(token);
	}
}
