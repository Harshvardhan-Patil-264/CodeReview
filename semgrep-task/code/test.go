/*
 * Purpose: Comprehensive test file for Golang coding rules - demonstrates all 20 rules
 * Author: Harsh Patil
 * Date: 2025-12-18
 * Modified By: N/A
 */

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"os"
	"time"
)

// ==========================================
// RULE 1: Always Handle Errors Immediately
// Why: Ignoring errors can cause silent failures
// ==========================================

// BAD: Not handling error
func badErrorHandling() {
	result, err := processData()
	fmt.Println(result) // err is ignored
}

// GOOD: Handling error immediately
func goodErrorHandling() {
	result, err := processData()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result)
}

// ==========================================
// RULE 2: Do Not Ignore Returned Errors
// Why: Go enforces explicit error handling
// ==========================================

// BAD: Ignoring error return
func badIgnoreError() {
	saveFile("data.txt") // error ignored
}

// GOOD: Checking returned error
func goodCheckError() {
	if err := saveFile("data.txt"); err != nil {
		log.Println(err)
	}
}

// ==========================================
// RULE 3: Avoid panic in Application Code
// Why: Panic crashes the program
// ==========================================

// BAD: Using panic
func badPanicUsage() {
	if configMissing {
		panic("config not found") // BAD
	}
}

// GOOD: Returning error
func goodErrorReturn() error {
	if configMissing {
		return errors.New("config not found")
	}
	return nil
}

// ==========================================
// RULE 4: Use Named Return Values Carefully
// Why: Overuse reduces readability
// ==========================================

// BAD: Overusing named returns
func badNamedReturns(a, b int) (sum int, product int, diff int) {
	sum = a + b
	product = a * b
	diff = a - b
	return
}

// GOOD: Simple named return when it improves clarity
func goodNamedReturn(a, b int) (sum int) {
	sum = a + b
	return
}

// ==========================================
// RULE 5: Prefer Short Variable Declarations
// Why: Keeps code concise and idiomatic
// ==========================================

// BAD: Using var declaration
func badVarDeclaration() {
	var count int = 10
	var name string = "test"
	fmt.Println(count, name)
}

// GOOD: Using short declaration
func goodShortDeclaration() {
	count := 10
	name := "test"
	fmt.Println(count, name)
}

// ==========================================
// RULE 6: Avoid Global Variables
// Why: Global state makes code harder to test
// ==========================================

// BAD: Global variable
var globalConfig string
var globalDB *sql.DB

// GOOD: Using struct with dependency injection
type Service struct {
	config string
	db     *sql.DB
}

func NewService(config string, db *sql.DB) *Service {
	return &Service{config: config, db: db}
}

// ==========================================
// RULE 7: Always Close Resources
// Why: Unclosed resources cause leaks
// ==========================================

// BAD: Not closing file
func badNoClose() error {
	file, err := os.Open("data.txt")
	if err != nil {
		return err
	}
	// Missing defer file.Close()
	return nil
}

// GOOD: Using defer to close
func goodDeferClose() error {
	file, err := os.Open("data.txt")
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}

// ==========================================
// RULE 8: Do Not Use defer Inside Loops
// Why: Defers inside loops can exhaust resources
// ==========================================

// BAD: defer in loop
func badDeferInLoop(files []string) error {
	for _, name := range files {
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		defer file.Close() // BAD: defer in loop
	}
	return nil
}

// GOOD: defer outside loop or in function
func goodDeferOutsideLoop(files []string) error {
	for _, name := range files {
		if err := processFile(name); err != nil {
			return err
		}
	}
	return nil
}

func processFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}

// ==========================================
// RULE 9: Use Context for Cancellation
// Why: Prevents goroutine leaks
// ==========================================

// BAD: No context
func badNoContext() error {
	// Long-running operation without context
	time.Sleep(10 * time.Second)
	return nil
}

// GOOD: Using context
func goodWithContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return nil
	}
}

// ==========================================
// RULE 10: Avoid Goroutine Leaks
// Why: Uncontrolled goroutines consume memory
// ==========================================

// BAD: Goroutine without exit mechanism
func badGoroutineLeak() {
	go func() {
		for {
			// Infinite loop with no way to exit
			time.Sleep(1 * time.Second)
		}
	}()
}

// GOOD: Goroutine with context
func goodGoroutineWithContext(ctx context.Context) {
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				// Do work
			}
		}
	}(ctx)
}

// ==========================================
// RULE 11: Prefer Interfaces Over Concrete Types
// Why: Improves flexibility and testability
// ==========================================

// BAD: Using concrete type
func badConcreteType(db *sql.DB) error {
	return nil
}

// GOOD: Using interface
type Database interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func goodInterfaceType(db Database) error {
	return nil
}

// ==========================================
// RULE 12: Avoid Empty Interface
// Why: Loses type safety
// ==========================================

// BAD: Using empty interface
func badEmptyInterface(data interface{}) {
	fmt.Println(data)
}

// GOOD: Using specific type
func goodSpecificType(id int) {
	fmt.Println(id)
}

// ==========================================
// RULE 13: Use Channels Safely
// Why: Unclosed channels cause goroutine leaks
// ==========================================

// BAD: Not closing channel
func badUnclosedChannel() {
	ch := make(chan int)
	go func() {
		ch <- 42
	}()
	// Missing close(ch)
}

// GOOD: Closing channel
func goodClosedChannel() {
	ch := make(chan int)
	defer close(ch)
	go func() {
		ch <- 42
	}()
}

// ==========================================
// RULE 14: Avoid time.After in Loops
// Why: Creates memory leaks
// ==========================================

// BAD: time.After in loop
func badTimeAfterInLoop() {
	for i := 0; i < 10; i++ {
		<-time.After(1 * time.Second) // BAD: memory leak
	}
}

// GOOD: Using time.NewTicker
func goodUseTicker() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for i := 0; i < 10; i++ {
		<-ticker.C
	}
}

// ==========================================
// RULE 15: Use crypto/rand for Security
// Why: math/rand is not cryptographically secure
// ==========================================

// BAD: Using math/rand
func badMathRand() {
	value := mathrand.Intn(100) // BAD: not secure
	fmt.Println(value)
}

// GOOD: Using crypto/rand
func goodCryptoRand() {
	value, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value)
}

// ==========================================
// RULE 16: Avoid Hard-Coded Secrets
// Why: Hard-coded credentials are a security risk
// ==========================================

// BAD: Hard-coded secrets
const badAPIKey = "sk_live_1234567890abcdef"
const badGitHubToken = "ghp_1234567890abcdef"
const badAWSKey = "AKIAIOSFODNN7EXAMPLE"

// GOOD: Using environment variables
func goodEnvSecrets() {
	apiKey := os.Getenv("API_KEY")
	githubToken := os.Getenv("GITHUB_TOKEN")
	awsKey := os.Getenv("AWS_ACCESS_KEY")
	fmt.Println(apiKey, githubToken, awsKey)
}

// ==========================================
// RULE 17: Use Struct Tags Correctly
// Why: Ensures proper serialization
// ==========================================

// BAD: Missing struct tags
type BadUser struct {
	ID    int
	Email string
}

// GOOD: With struct tags
type GoodUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

// ==========================================
// RULE 18: Keep Functions Small and Focused
// Why: Improves readability and testing
// ==========================================

// BAD: Long function doing too much
func badLongFunction() error {
	validateInput()
	checkPermissions()
	loadConfig()
	connectDatabase()
	processData()
	saveResults()
	sendNotification()
	logActivity()
	updateMetrics()
	cleanupTemp()
	archiveOldData()
	generateReport()
	return nil
}

// GOOD: Small focused function
func goodSmallFunction(user GoodUser) error {
	if user.ID == 0 {
		return errors.New("invalid user ID")
	}
	return nil
}

// ==========================================
// RULE 19: Avoid SQL String Concatenation
// Why: Prevents SQL injection
// ==========================================

// BAD: SQL injection vulnerability
func badSQLInjection(db *sql.DB, userID string) error {
	query := "SELECT * FROM users WHERE id = " + userID // BAD
	_, err := db.Query(query)
	return err
}

// GOOD: Using parameterized queries
func goodParameterizedQuery(db *sql.DB, userID string) error {
	query := "SELECT * FROM users WHERE id = ?"
	_, err := db.Query(query, userID)
	return err
}

// ==========================================
// RULE 20: Follow Go Formatting (gofmt)
// Why: Ensures consistent code style
// Note: Run gofmt -w *.go
// ==========================================

// Helper functions
func processData() (string, error) {
	return "data", nil
}

func saveFile(name string) error {
	return nil
}

func validateInput() {}
func checkPermissions() {}
func loadConfig() {}
func connectDatabase() {}
func processData2() {}
func saveResults() {}
func sendNotification() {}
func logActivity() {}
func updateMetrics() {}
func cleanupTemp() {}
func archiveOldData() {}
func generateReport() {}

var configMissing = false

func main() {
	fmt.Println("Golang coding rules test file")
}
