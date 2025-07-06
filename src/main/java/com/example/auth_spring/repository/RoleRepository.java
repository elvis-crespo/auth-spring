package com.example.auth_spring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.auth_spring.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

}
