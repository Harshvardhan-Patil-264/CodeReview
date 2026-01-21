// Purpose: Comprehensive test file to trigger all 25 custom Go rules and 78 community security rules
// Author: Harshvardhan Patil
// Date: 2026-01-20
// Modified By: AI Assistant

package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
)

// Global variable (triggers go-rule-6-global-var)
var globalDB *sql.DB

// ==========================================
// CUSTOM RULES TRIGGERS (25 rules)
// ==========================================

// Trigger: go-rule-1-unhandled-error
func unhandledError() {
	data, err := os.ReadFile("test.txt")
	// Error not checked - violates rule 1
	fmt.Println(string(data))
}

// Trigger: go-rule-3-avoid-panic
func usePanic() {
	panic("This should not panic in production") // Violates rule 3
}

// Trigger: go-rule-8-defer-in-loop
func deferInLoop() {
	for i := 0; i < 10; i++ {
		defer fmt.Println(i) // Violates rule 8
	}
}

// Trigger: go-rule-10-goroutine-leak
func goroutineLeak() {
	go func() {
		// No context or done channel - potential leak
		time.Sleep(time.Hour)
	}()
}

// Trigger: go-rule-12-empty-interface
func emptyInterface(data interface{}) { // Violates rule 12
	fmt.Println(data)
}

// Trigger: go-rule-13-unclosed-channel
func unchannelClosed() {
	ch := make(chan int) // Channel never closed
	go func() {
		ch <- 42
	}()
}

// Trigger: go-rule-14-time-after-leak
func timeAfterInLoop() {
	for i := 0; i < 100; i++ {
		<-time.After(time.Second) // Memory leak - violates rule 14
	}
}

// Trigger: go-rule-15-weak-random
func weakRandom() {
	token := make([]byte, 32)
	rand.Read(token) // Should use crypto/rand - violates rule 15
}

// Trigger: go-rule-18-long-function
func veryLongFunction() {
	fmt.Println("Line 1")
	fmt.Println("Line 2")
	fmt.Println("Line 3")
	fmt.Println("Line 4")
	fmt.Println("Line 5")
	fmt.Println("Line 6")
	fmt.Println("Line 7")
	fmt.Println("Line 8")
	fmt.Println("Line 9")
	fmt.Println("Line 10")
	fmt.Println("Line 11")
	fmt.Println("Line 12")
}

// Trigger: go-rule-19-sql-injection
func sqlInjection(db *sql.DB, userInput string) {
	query := "SELECT * FROM users WHERE name = '" + userInput + "'" // SQL injection
	db.Query(query)
}

// Trigger: go-rule-20-no-fmt-println
func useFmtPrintln() {
	fmt.Println("This should use proper logging") // Violates rule 20
	fmt.Printf("Format string: %s\n", "test")
	fmt.Print("Another print")
}

// Trigger: go-rule-23-variable-naming-camelcase
func variableNaming() {
	user_name := "John" // Should be userName
	fmt.Println(user_name)
}

// Trigger: go-rule-24-constant-naming
const max_retries = 5 // Should be MaxRetries or maxRetries

// ==========================================
// COMMUNITY RULES TRIGGERS (78 rules)
// ==========================================

// Trigger: database-sqli, tainted-sql-string
func sqlInjectionTainted(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", "connection_string")
	userInput := r.URL.Query().Get("name")
	
	// Tainted SQL injection
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	db.Query(query)
	
	// String concatenation SQL injection
	db.Exec("DELETE FROM users WHERE id = " + userInput)
}

// Trigger: session-cookie-missing-httponly, session-cookie-missing-secure
func insecureCookies() {
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	// Missing HttpOnly and Secure flags
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: false, // Violates session-cookie-missing-httponly
		Secure:   false, // Violates session-cookie-missing-secure
	}
}

// Trigger: session-cookie-samesitenone
func sameSiteNone() {
	store := sessions.NewCookieStore([]byte("key"))
	store.Options = &sessions.Options{
		SameSite: http.SameSiteNoneMode, // Violates session-cookie-samesitenone
	}
}

// Trigger: websocket-missing-origin-check
func websocketNoOriginCheck(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{} // No CheckOrigin function
	upgrader.Upgrade(w, r, nil)
}

// Trigger: gorm-dangerous-method-usage
func gormDangerousMethod(db *gorm.DB, r *http.Request) {
	userInput := r.URL.Query().Get("order")
	
	// Dangerous GORM method with user input
	db.Order(userInput).Find(&[]string{})
	db.Select(userInput).Find(&[]string{})
}

// Trigger: grpc-client-insecure-connection
func grpcInsecureClient() {
	// Insecure gRPC connection
	// grpc.Dial("localhost:50051", grpc.WithInsecure())
}

// Trigger: jwt-go-none-algorithm
func jwtNoneAlgorithm() {
	token := jwt.New(jwt.SigningMethodNone) // Violates jwt-go-none-algorithm
	fmt.Println(token)
}

// Trigger: hardcoded-jwt-key
func hardcodedJWTKey() {
	token := jwt.New(jwt.SigningMethodHS256)
	secretKey := []byte("hardcoded-secret-key-123") // Hardcoded credential
	token.SignedString(secretKey)
}

// Trigger: math-random-used
func mathRandomUsed() {
	// Using math/rand instead of crypto/rand
	randomNum := rand.Intn(100)
	fmt.Println(randomNum)
}

// Trigger: missing-ssl-minversion
func missingTLSMinVersion() {
	config := &tls.Config{
		// MinVersion missing - defaults to TLS 1.2
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	fmt.Println(config)
}

// Trigger: ssl-v3-is-insecure
func sslV3Insecure() {
	config := &tls.Config{
		MinVersion: tls.VersionSSL30, // SSLv3 is insecure
	}
	fmt.Println(config)
}

// Trigger: tls-with-insecure-cipher
func insecureCipher() {
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,        // Insecure
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,   // Insecure
		},
	}
	fmt.Println(config)
}

// Trigger: use-of-md5, use-of-sha1, use-of-DES, use-of-rc4
func weakCryptography() {
	// MD5 - weak hash
	md5Hash := md5.New()
	md5Hash.Write([]byte("password"))
	
	// SHA1 - weak hash
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte("password"))
	
	// DES - weak cipher
	des.NewCipher([]byte("12345678"))
	
	// RC4 - weak cipher
	rc4.NewCipher([]byte("key"))
}

// Trigger: use-of-weak-rsa-key
func weakRSAKey() {
	// RSA key less than 2048 bits
	// rsa.GenerateKey(rand.Reader, 1024)
}

// Trigger: string-formatted-query
func stringFormattedQuery(db *sql.DB, userID string) {
	// String-formatted SQL query
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
	db.Query(query)
	
	db.Exec("UPDATE users SET name = '" + userID + "'")
}

// Trigger: avoid-bind-to-all-interfaces
func bindToAllInterfaces() {
	// Binding to 0.0.0.0 exposes server publicly
	http.ListenAndServe("0.0.0.0:8080", nil)
	http.ListenAndServe(":9090", nil)
}

// Trigger: cookie-missing-httponly, cookie-missing-secure
func insecureHTTPCookies() {
	cookie := &http.Cookie{
		Name:  "session",
		Value: "abc123",
		// HttpOnly and Secure missing
	}
	fmt.Println(cookie)
}

// Trigger: formatted-template-string
func formattedTemplate(userInput string) {
	// Formatted template - XSS risk
	tmpl := template.HTML(fmt.Sprintf("<div>%s</div>", userInput))
	fmt.Println(tmpl)
}

// Trigger: use-tls
func noTLS() {
	// HTTP without TLS
	http.ListenAndServe(":8080", nil)
}

// Trigger: dangerous-exec-command
func dangerousExecCommand(userInput string) {
	// Command injection risk
	exec.Command("sh", "-c", userInput).Run()
	exec.Command(userInput).Run()
}

// Trigger: dangerous-syscall-exec
func dangerousSyscallExec(userCmd string) {
	// Syscall exec with user input
	syscall.Exec(userCmd, []string{userCmd}, os.Environ())
}

// Trigger: md5-used-as-password
func md5Password(password string) {
	// MD5 used for password hashing
	hash := md5.Sum([]byte(password))
	fmt.Printf("%x", hash)
}

// Trigger: reflect-makefunc
func reflectMakeFunc() {
	// Dangerous reflection
	reflect.MakeFunc(reflect.TypeOf(func() {}), func([]reflect.Value) []reflect.Value {
		return nil
	})
}

// Trigger: unsafe-reflect-by-name
func unsafeReflectByName(methodName string) {
	val := reflect.ValueOf(&struct{}{})
	// User-controlled method name
	val.MethodByName(methodName)
}

// Trigger: use-of-unsafe-block
func useUnsafeBlock() {
	var x int = 42
	// Using unsafe package
	ptr := unsafe.Pointer(&x)
	fmt.Println(ptr)
}

// Trigger: bad-tmp-file-creation
func badTmpFile() {
	// Creating file in /tmp without using io.CreateTemp
	os.Create("/tmp/myfile.txt")
	os.WriteFile("/tmp/data.txt", []byte("data"), 0644)
}

// Trigger: potential-dos-via-decompression-bomb
func decompressionBomb(r io.Reader) {
	// No size limit on decompression
	io.Copy(os.Stdout, r)
}

// Trigger: wip-xss-using-responsewriter-and-printf
func xssResponseWriter(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("name")
	template := "Hello, %s!"
	
	// XSS vulnerability
	w.Write([]byte(fmt.Sprintf(template, userInput)))
}

// Trigger: unescaped-data-in-htmlattr, unescaped-data-in-js, unescaped-data-in-url
func unescapedTemplateData(userInput string) {
	// Unescaped HTML attribute
	template.HTMLAttr(fmt.Sprintf("class='%s'", userInput))
	
	// Unescaped JavaScript
	template.JS(fmt.Sprintf("var x = '%s';", userInput))
	
	// Unescaped URL
	template.URL(fmt.Sprintf("/page?id=%s", userInput))
}

// Trigger: pprof-debug-exposure
// import _ "net/http/pprof"
func pprofExposed() {
	// Pprof endpoint exposed publicly
	http.ListenAndServe(":6060", nil)
}

// Trigger: fs-directory-listing
func directoryListing() {
	// Directory listing enabled
	fs := http.FileServer(http.Dir("/var/www"))
	http.ListenAndServe(":8080", fs)
}

func main() {
	fmt.Println("Vulnerable Go code for testing Semgrep rules")
	fmt.Println("This file intentionally contains security vulnerabilities")
	fmt.Println("DO NOT use this code in production!")
}
