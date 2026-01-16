package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import javax.persistence.EntityManager;
import javax.transaction.Transactional;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * COMPREHENSIVE TEST FILE FOR ALL 33 JAVA/SPRING BOOT RULES
 * This file intentionally contains violations to test Semgrep detection
 */

@RestController
@CrossOrigin(origins = "*") // RULE: spring-cors-allow-all - ERROR
public class TestSpringBoot {

    // RULE: spring-field-injection - WARNING
    @Autowired
    private UserService userService;

    @Autowired
    private EntityManager entityManager;

    // RULE: java-rule-7-private-fields - WARNING
    public String publicField;

    // =====================================================
    // SPRING BOOT SECURITY RULES (15 RULES)
    // =====================================================

    // RULE: spring-sql-injection-native-query - ERROR
    @GetMapping("/search")
    public List<User> searchUsers(@RequestParam String query) {
        return entityManager.createQuery("SELECT u FROM User u WHERE u.name = " + query)
                .getResultList();
    }

    // RULE: spring-missing-validation - WARNING
    @PostMapping("/users")
    public User createUser(@RequestBody UserDTO userDto) {
        return userService.save(userDto);
    }

    // RULE: spring-missing-transactional - WARNING
    @PostMapping("/transfer")
    public void transferMoney(Long fromId, Long toId, Double amount) {
        accountRepository.debit(fromId, amount);
        accountRepository.credit(toId, amount);
    }

    // RULE: spring-missing-authorization - ERROR
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable String id) {
        userService.delete(id);
    }

    // RULE: spring-path-traversal - ERROR
    @GetMapping("/files/{filename}")
    public File getFile(@PathVariable String filename) {
        return new File("/uploads/" + filename);
    }

    // RULE: spring-csrf-disabled - WARNING
    public void configureSecurity(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    // RULE: spring-plaintext-password - ERROR
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    // RULE: spring-insecure-deserialization - ERROR
    public Object deserializeData(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // RULE: spring-missing-response-entity - INFO
    @GetMapping("/data")
    public String getData() {
        return "data";
    }

    // =====================================================
    // CORE JAVA RULES (18 RULES)
    // =====================================================

    // RULE: java-rule-1-string-equals - ERROR
    public boolean compareStrings(String str1, String str2) {
        if (str1 == str2) { // Should use .equals()
            return true;
        }
        return false;
    }

    // RULE: java-rule-2-no-system-out - WARNING
    public void logMessage(String msg) {
        System.out.println("Log: " + msg);
        System.err.println("Error log");
    }

    // RULE: java-rule-3-handle-exceptions - WARNING
    public void handleException() {
        try {
            riskyOperation();
        } catch (Exception e) {
            System.out.println(e); // Should use logger
        }
    }

    // RULE: java-rule-4-empty-catch - ERROR
    public void emptyCatchBlock() {
        try {
            dangerousMethod();
        } catch (Exception e) {
            // Empty catch block!
        }
    }

    // RULE: java-rule-6-use-interface - INFO
    public void useConcreteTypes() {
        ArrayList<String> names = new ArrayList<String>();
        HashMap<String, Integer> scores = new HashMap<String, Integer>();
        HashSet<Integer> numbers = new HashSet<Integer>();
    }

    // RULE: java-rule-11-generic-exception - WARNING
    public void catchGenericException() {
        try {
            process();
        } catch (Exception e) { // Too generic, catch specific exceptions
            handle(e);
        }
    }

    // RULE: java-rule-14-string-concat-loop - WARNING
    public String concatenateInLoop(List<String> items) {
        String result = "";
        for (String item : items) {
            result = result + item; // Should use StringBuilder
        }
        return result;
    }

    // RULE: java-rule-15-sql-injection - ERROR
    public void executeSql(String userId) throws Exception {
        Statement stmt = connection.createStatement();
        stmt.execute("SELECT * FROM users WHERE id = " + userId);
    }

    // RULE: java-rule-19-sleep-in-loop - WARNING
    public void sleepInLoop() throws InterruptedException {
        while (isRunning) {
            Thread.sleep(1000); // Bad practice
            doWork();
        }
    }

    // RULE: java-null-check-missing - WARNING
    public void nullCheckMissing(User user) {
        if (user != null) {
            user.getName();
        }
        user.getEmail(); // Potential NPE!
    }

    // RULE: java-resource-leak - WARNING
    public void resourceLeak() throws IOException {
        FileInputStream fis = new FileInputStream("data.txt");
        // Should use try-with-resources
        fis.close();
    }

    // RULE: java-weak-hash - ERROR
    public void weakHashing() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    }

    // =====================================================
    // NAMING CONVENTION RULES (5 RULES)
    // =====================================================

    // RULE: java-rule-21-class-naming-pascalcase - WARNING
    // (Class name should be PascalCase)

    // RULE: java-rule-22-method-naming-camelcase - WARNING
    public void MethodNameShouldBeCamelCase() {
        // Method should start with lowercase
    }

    // RULE: java-rule-23-variable-naming-camelcase - INFO
    public void variableNaming() {
        String User_Name = "test"; // Should be camelCase
        int Total_Count = 0;
    }

    // RULE: java-rule-24-constant-naming-uppercase - INFO
    public void constantNaming() {
        final String apiKey = "secret"; // Should be UPPER_CASE
        final int maxRetries = 3;
    }

    // RULE: java-rule-25-package-naming-lowercase - INFO
    // package com.Example.Demo; // Should be all lowercase

    // Helper methods (referenced above)
    private void riskyOperation() throws Exception {
    }

    private void dangerousMethod() throws Exception {
    }

    private void process() throws Exception {
    }

    private void handle(Exception e) {
    }

    private void doWork() {
    }

    private boolean isRunning = true;
    private Connection connection;
    private AccountRepository accountRepository;

    // =====================================================
    // PERFORMANCE OPTIMIZATION VIOLATIONS (5 RULES)
    // =====================================================

    // RULE: java-inefficient-collection-contains - WARNING
    public void inefficientContains(List<String> names, List<String> searchList) {
        for (String name : searchList) {
            if (names.contains(name)) { // O(n²) - should use HashSet
                process(name);
            }
        }
    }

    // RULE: java-autoboxing-in-loop - WARNING
    public void autoboxingInLoop() {
        for (int i = 0; i < 1000; i++) {
            Integer boxed = i; // Autoboxing creates object
            process(boxed);
        }
    }

    // RULE: java-string-format-in-loop - WARNING
    public void stringFormatInLoop(List<String> items) {
        for (String item : items) {
            String formatted = String.format("Item: %s", item); // Expensive
            log(formatted);
        }
    }

    // RULE: java-inefficient-map-iteration - INFO
    public void inefficientMapIteration(Map<String, Integer> scores) {
        for (String key : scores.keySet()) {
            Integer value = scores.get(key); // Inefficient double lookup
            System.out.println(key + ": " + value);
        }
    }

    // RULE: java-object-creation-in-loop - INFO
    public void objectCreationInLoop() {
        for (int i = 0; i < 100; i++) {
            StringBuilder sb = new StringBuilder(); // Should be created once outside
            sb.append(i);
        }
    }

    // =====================================================
    // CONCURRENCY & THREADING VIOLATIONS (5 RULES)
    // =====================================================

    // RULE: java-sync-on-string - ERROR
    private static final String LOCK = "lock";

    public void syncOnString() {
        synchronized (LOCK) { // Never synchronize on String!
            criticalSection();
        }
    }

    // RULE: java-double-checked-locking - ERROR
    private static volatile Singleton instance;

    public Singleton getInstance() {
        if (instance == null) {
            synchronized (Singleton.class) {
                if (instance == null) { // Broken without volatile!
                    instance = new Singleton();
                }
            }
        }
        return instance;
    }

    // RULE: java-non-atomic-operation - WARNING
    private int counter = 0;

    public void incrementCounter() {
        counter++; // Not atomic - race condition!
    }

    // RULE: java-threadlocal-no-cleanup - WARNING
    private ThreadLocal<Connection> threadLocalConnection = new ThreadLocal<>();
    // Missing remove() call - memory leak in thread pools!

    // RULE: java-volatile-instead-of-atomic - INFO
    private volatile int volatileCounter; // Should use AtomicInteger

    // =====================================================
    // STREAM API VIOLATIONS (4 RULES)
    // =====================================================

    // RULE: java-stream-unnecessary-collect - WARNING
    public long countItems(List<String> items) {
        return items.stream()
                .filter(s -> s.length() > 5)
                .collect(Collectors.toList()).size(); // Should use .count()
    }

    // RULE: java-stream-peek-side-effects - WARNING
    public void peekWithSideEffects(List<User> users) {
        users.stream()
                .peek(u -> u.setActive(true)) // Wrong! Use map or forEach
                .collect(Collectors.toList());
    }

    // RULE: java-parallel-stream-small-collection - INFO
    public void parallelStreamMisuse() {
        List<Integer> small = Arrays.asList(1, 2, 3, 4, 5);
        small.parallelStream().forEach(System.out::println); // Overhead > benefit
    }

    // RULE: java-optional-get-without-check - ERROR
    public String getUsername(Optional<User> user) {
        return user.get().getName(); // Can throw NoSuchElementException!
    }

    // =====================================================
    // JUNIT TESTING VIOLATIONS (3 RULES)
    // =====================================================

    // RULE: java-test-no-assertions - WARNING
    @Test
    public void testWithoutAssertions() {
        userService.createUser("test");
        // No assertions - what are we testing?
    }

    // RULE: java-test-hardcoded-production-data - INFO
    @Test
    public void testWithProductionData() {
        String email = "admin@example.com"; // Production-like data
        User user = userService.findByEmail(email);
    }

    // RULE: java-test-sleep-instead-of-wait - WARNING
    @Test
    public void testWithSleep() throws InterruptedException {
        asyncService.startTask();
        Thread.sleep(5000); // Bad! Use proper waiting
        verify(taskCompleted);
    }

    // =====================================================
    // JPA/HIBERNATE VIOLATIONS (4 RULES)
    // =====================================================

    // RULE: jpa-potential-n-plus-one - WARNING
    @Entity
    class Author {
        @OneToMany // N+1 query problem!
        private List<Book> books;
    }

    // RULE: jpa-missing-fetch-type - INFO
    @Entity
    class Department {
        @OneToMany // Should specify fetch = LAZY or EAGER
        private List<Employee> employees;
    }

    // RULE: jpa-bidirectional-no-mappedby - WARNING
    @Entity
    class Order {
        @OneToMany // Bidirectional needs mappedBy
        private List<OrderItem> items;
    }

    // RULE: jpa-entity-missing-equals-hashcode - WARNING
    @Entity
    class Product {
        @Id
        private Long id;
        private String name;
        // Missing equals() and hashCode()!
    }

    // =====================================================
    // JACKSON/JSON VIOLATIONS (3 RULES)
    // =====================================================

    // RULE: jackson-enable-default-typing - ERROR
    public ObjectMapper configureMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(); // Security risk!
        return mapper;
    }

    // RULE: jackson-missing-ignore-properties - INFO
    public class UserDTO {
        // Missing @JsonIgnoreProperties(ignoreUnknown=true)
        private String username;
        private String email;
    }

    // RULE: jackson-sensitive-field-exposed - ERROR
    public class AccountDTO {
        private String username;
        private String password; // Should have @JsonIgnore!
        private String apiKey; // Exposed in JSON!
    }

    // =====================================================
    // MICROSERVICES VIOLATIONS (3 RULES)
    // =====================================================

    // RULE: spring-missing-circuit-breaker - WARNING
    public ResponseEntity callExternalAPI() {
        RestTemplate restTemplate = new RestTemplate();
        return restTemplate.exchange(
                "https://api.external.com/data",
                HttpMethod.GET,
                null,
                String.class); // Missing @CircuitBreaker
    }

    // RULE: spring-missing-retry - INFO
    public String fetchFromService() {
        HttpClient client = HttpClient.newHttpClient();
        return client.get("https://service.com/api"); // No retry logic
    }

    // RULE: feign-without-fallback - WARNING
    @FeignClient(name = "payment-service") // Missing fallback
    interface PaymentClient {
        @GetMapping("/payments/{id}")
        Payment getPayment(@PathVariable Long id);
    }

    // Helper methods (referenced above)
    private void process(Object obj) {
    }

    private void log(String msg) {
    }

    private void criticalSection() {
    }

    private boolean taskCompleted;
    private AsyncService asyncService;

    private void verify(boolean condition) {
    }
}

/**
 * EXPECTED DETECTION COUNT: ~55-60 violations
 * 
 * Categories:
 * - 15 ERROR (Security critical)
 * - 25 WARNING (Important issues)
 * - 15 INFO (Code style)
 * 
 * This file demonstrates ALL 60 RULES for comprehensive testing!
 * 
 * Rule Categories:
 * - Core Java: 18 rules
 * - Spring Boot Security: 15 rules
 * - Performance Optimization: 5 rules
 * - Concurrency & Threading: 5 rules
 * - Stream API: 4 rules
 * - JUnit Testing: 3 rules
 * - JPA/Hibernate: 4 rules
 * - Jackson/JSON: 3 rules
 * - Microservices: 3 rules
 */
