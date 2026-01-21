/*
 * Purpose: Comprehensive Java vulnerable test file to trigger all custom and community rules
 * Author: Harshvardhan Patil
 * Date: 2026-01-20
 * Modified By: AI Assistant
 */

// ==========================================
// JAVA VULNERABLE CODE - TEST FILE
// ==========================================
// This file contains intentional security vulnerabilities
// DO NOT use in production!

package com.example.vulnerable;

import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Random;
import javax.servlet.http.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.net.URL;
import java.util.regex.Pattern;

public class TestVulnerable {

    // ==========================================
    // SQL INJECTION VULNERABILITIES
    // ==========================================

    public void sqlInjection(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password");

        // SQL Injection - string concatenation
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        // SQL Injection - string format
        String query2 = String.format("DELETE FROM users WHERE id = %s", userInput);
        stmt.execute(query2);
    }

    // ==========================================
    // COMMAND INJECTION
    // ==========================================

    public void commandInjection(String userInput) throws IOException {
        // Command injection via Runtime.exec
        Runtime.getRuntime().exec("ls " + userInput);

        // Command injection via ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", userInput);
        pb.start();
    }

    // ==========================================
    // PATH TRAVERSAL
    // ==========================================

    public void pathTraversal(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");

        // Path traversal vulnerability
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);

        // Path traversal with FileReader
        FileReader reader = new FileReader("./files/" + filename);
    }

    // ==========================================
    // XSS VULNERABILITIES
    // ==========================================

    public void xssVulnerability(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String userInput = request.getParameter("name");

        // XSS - direct output
        response.getWriter().write("<h1>Hello " + userInput + "</h1>");

        // Reflected XSS
        PrintWriter out = response.getWriter();
        out.println("<div>" + userInput + "</div>");
    }

    // ==========================================
    // WEAK CRYPTOGRAPHY
    // ==========================================

    public void weakCrypto() throws Exception {
        String password = "secret123";

        // MD5 - weak hash
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash = md5.digest(password.getBytes());

        // SHA1 - weak hash
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(password.getBytes());

        // DES - weak cipher
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }

    // ==========================================
    // INSECURE RANDOM
    // ==========================================

    public String insecureRandom() {
        // Using Random instead of SecureRandom
        Random random = new Random();
        int token = random.nextInt();
        String sessionId = String.valueOf(random.nextLong());

        return sessionId;
    }

    // ==========================================
    // HARDCODED CREDENTIALS
    // ==========================================

    private static final String DATABASE_PASSWORD = "admin123"; // Hardcoded password
    private static final String API_KEY = "sk_live_1234567890abcdef"; // Hardcoded API key
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    public Connection connectDatabase() throws SQLException {
        // Hardcoded credentials
        return DriverManager.getConnection(
                "jdbc:mysql://localhost/db",
                "root",
                "password123");
    }

    // ==========================================
    // INSECURE DESERIALIZATION
    // ==========================================

    public Object insecureDeserialization(InputStream input)
            throws IOException, ClassNotFoundException {
        // Unsafe deserialization
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
        return obj;
    }

    // ==========================================
    // XML EXTERNAL ENTITY (XXE)
    // ==========================================

    public void xxeVulnerability(String xmlData) throws Exception {
        // XXE vulnerability - no secure processing
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }

    // ==========================================
    // OPEN REDIRECT
    // ==========================================

    public void openRedirect(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("url");

        // Open redirect vulnerability
        response.sendRedirect(url);
    }

    // ==========================================
    // MISSING INPUT VALIDATION
    // ==========================================

    public void createUser(HttpServletRequest request) throws SQLException {
        // No input validation
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        Connection conn = connectDatabase();
        String query = "INSERT INTO users VALUES ('" + username + "', '" + password + "')";
        conn.createStatement().execute(query);
    }

    // ==========================================
    // INFORMATION DISCLOSURE
    // ==========================================

    public void handleError(Exception e, HttpServletResponse response) throws IOException {
        // Exposing stack traces
        response.getWriter().write("Error: " + e.getMessage());
        e.printStackTrace(response.getWriter()); // Information disclosure
    }

    // ==========================================
    // UNSAFE FILE OPERATIONS
    // ==========================================

    public void unsafeFileOps(String filename) throws IOException {
        // Unsafe file write
        FileWriter writer = new FileWriter(filename);
        writer.write("data");

        // Unsafe file delete
        new File(filename).delete();

        // Unsafe chmod
        new File(filename).setExecutable(true, false);
    }

    // ==========================================
    // REGEX DOS (ReDoS)
    // ==========================================

    public boolean regexDos(String userInput) {
        // Catastrophic backtracking
        Pattern pattern = Pattern.compile("^(a+)+$");
        return pattern.matcher(userInput).matches();
    }

    // ==========================================
    // MISSING AUTHENTICATION
    // ==========================================

    public void adminPanel(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException {
        // No authentication check
        Connection conn = connectDatabase();
        ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM users");

        while (rs.next()) {
            response.getWriter().write(rs.getString("username"));
        }
    }

    // ==========================================
    // WEAK SSL/TLS
    // ==========================================

    public void weakSSL() throws Exception {
        // Weak SSL/TLS configuration
        javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("SSLv3");

        // Disable certificate validation
        javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[] {
                new javax.net.ssl.X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
    }

    // ==========================================
    // LDAP INJECTION
    // ==========================================

    public void ldapInjection(String userInput) throws Exception {
        // LDAP injection
        javax.naming.directory.DirContext ctx = null;
        String filter = "(uid=" + userInput + ")";
        ctx.search("ou=users", filter, null);
    }

    // ==========================================
    // XPATH INJECTION
    // ==========================================

    public void xpathInjection(String userInput) throws Exception {
        // XPath injection
        javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "//user[@name='" + userInput + "']";
        xpath.evaluate(expression, (Object) null);
    }

    // ==========================================
    // NULL POINTER DEREFERENCE
    // ==========================================

    public void nullPointerDereference(String input) {
        String value = null;

        // Potential null pointer dereference
        if (input.equals("test")) {
            value = "result";
        }

        System.out.println(value.length()); // NPE if input != "test"
    }

    // ==========================================
    // RESOURCE LEAK
    // ==========================================

    public void resourceLeak(String filename) throws IOException {
        // Resource leak - no try-with-resources
        FileInputStream fis = new FileInputStream(filename);
        fis.read();
        // File not closed - resource leak
    }

    // ==========================================
    // INSECURE COOKIE
    // ==========================================

    public void insecureCookie(HttpServletResponse response) {
        // Missing secure and httpOnly flags
        Cookie cookie = new Cookie("session", "abc123");
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
    }

    // ==========================================
    // UNSAFE REFLECTION
    // ==========================================

    public void unsafeReflection(String className) throws Exception {
        // Unsafe reflection with user input
        Class<?> clazz = Class.forName(className);
        Object instance = clazz.newInstance();
    }

    // ==========================================
    // MISSING CSRF PROTECTION
    // ==========================================

    public void transferMoney(HttpServletRequest request) throws SQLException {
        // No CSRF protection
        String amount = request.getParameter("amount");
        String toAccount = request.getParameter("to");

        // Process transfer without CSRF token
        Connection conn = connectDatabase();
        String query = "INSERT INTO transfers VALUES ('" + amount + "', '" + toAccount + "')";
        conn.createStatement().execute(query);
    }

    public static void main(String[] args) {
        System.out.println("Vulnerable Java application for testing");
        System.out.println("DO NOT use in production!");
    }
}
