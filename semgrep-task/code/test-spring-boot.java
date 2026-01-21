package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import javax.persistence.EntityManager;
import java.io.File;

@RestController
@CrossOrigin(origins = "*") // VIOLATION: spring-cors-allow-all
public class UserController {

    @Autowired // VIOLATION: spring-field-injection
    private UserService userService;

    @Autowired
    private EntityManager entityManager;

    @PostMapping("/users") // VIOLATION: spring-missing-validation (no @Valid)
    public User createUser(@RequestBody UserDTO userDto) {
        return userService.save(userDto); // VIOLATION: spring-missing-transactional
    }

    @DeleteMapping("/users/{id}") // VIOLATION: spring-missing-authorization
    public void deleteUser(@PathVariable String id) {
        userService.delete(id);
    }

    @GetMapping("/search") // VIOLATION: spring-sql-injection-native-query
    public void searchUsers(String query) {
        entityManager.createQuery("SELECT u FROM User u WHERE name = " + query);
    }

    @GetMapping("/files/{filename}") // VIOLATION: spring-path-traversal
    public File getFile(@PathVariable String filename) {
        return new File("/uploads/" + filename);
    }

    public boolean checkPassword(String input, String stored) {
        if (input == stored) { // VIOLATION: java-rule-1-string-equals
            return true;
        }
        return false;
    }

    public void logError(Exception e) {
        System.out.println("Error: " + e.getMessage()); // VIOLATION: java-rule-2-no-system-out
    }

    public void riskyOperation() {
        try {
            dangerousMethod();
        } catch (Exception e) { // VIOLATION: java-rule-4-empty-catch
        }
    }
}
