package com.example.auth_spring.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.auth_spring.dto.NewUserDto;
import com.example.auth_spring.entities.Role;
import com.example.auth_spring.entities.User;
import com.example.auth_spring.enums.RoleList;
import com.example.auth_spring.jwt.JwtUtil;
import com.example.auth_spring.repository.RoleRepository;


@Service
public class AuthService {
    private final UserService userService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthService(UserService userService, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    public String authenticate(String userName, String password) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, password);

        Authentication authResult = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authResult);
        String jwt = jwtUtil.generateToken(authResult);
        return jwt;                
    }

    public void registerUser(NewUserDto newUserDto) {
        if(userService.existsByUserName(newUserDto.getUserName())) {
            throw new RuntimeException("Username already exists");
        }

        Role roleUser = roleRepository.findByName(RoleList.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found: " + RoleList.ROLE_USER));
        User user = new User(newUserDto.getUserName(),passwordEncoder.encode(newUserDto.getPassword()), roleUser);
        userService.save(user);
    }
}
