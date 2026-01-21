package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import javax.persistence.EntityManager;
import java.io.File;

@RestController
@CrossOrigin(origins = "*") // Should trigger: spring-cors-allow-all
public class UserController {

    @Autowired // Should trigger: spring-field-injection
    private UserService userService;

    @Autowired
    private EntityManager entityManager;

    // Missing @Valid - should trigger: spring-missing-validation
    @PostMapping("/users")
    public User createUser(@RequestBody UserDTO userDto) {
        return userService.save(userDto);
    }

    // Missing @PreAuthorize - should trigger: spring-missing-authorization
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable String id) {
        userService.delete(id);
    }

    // SQL Injection - should trigger: spring-sql-injection-native-query
    @GetMapping("/search")
    public void searchUsers(String query) {
        entityManager.createQuery("SELECT u FROM User u WHERE u.name = " + query);
    }

    // Path Traversal - should trigger: spring-path-traversal
    @GetMapping("/files/{filename}")
    public File getFile(@PathVariable String filename) {
        return new File("/uploads/" + filename);
    }

    // Should trigger: java-rule-1-string-equals
    public boolean checkPassword(String input, String stored) {
        if (input == stored) {
            return true;
        }
        return false;
    }

    // Should trigger: java-rule-2-no-system-out
    public void logError(Exception e) {
        System.out.println("Error: " + e.getMessage());
    }

    // Should trigger: java-rule-4-empty-catch
    public void riskyOperation() {
        try {
            dangerousMethod();
        } catch (Exception e) {
        }
    }
}
