// Purpose: Comprehensive JavaScript vulnerable test file to trigger all custom and community rules
// Author: Harshvardhan Patil  
// Date: 2026-01-20
// Modified By: AI Assistant

// ==========================================
// JAVASCRIPT VULNERABLE CODE - TEST FILE
// ==========================================
// This file contains intentional security vulnerabilities
// DO NOT use in production!

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

// ==========================================
// SQL INJECTION VULNERABILITIES
// ==========================================

function sqlInjection(userInput) {
    const db = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password'
    });

    // SQL Injection - string concatenation
    const query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    db.query(query, (err, results) => {
        console.log(results);
    });

    // SQL Injection - template literals
    const query2 = `DELETE FROM users WHERE id = ${userInput}`;
    db.query(query2);
}

// ==========================================
// XSS VULNERABILITIES
// ==========================================

const app = express();

app.get('/xss', (req, res) => {
    const userInput = req.query.name;

    // XSS - direct HTML injection
    res.send("<h1>Hello " + userInput + "</h1>");

    // XSS - innerHTML
    const html = `<div>${userInput}</div>`;
    res.send(html);
});

app.get('/reflected-xss', (req, res) => {
    // Reflected XSS
    res.write(req.query.search);
    res.end();
});

// ==========================================
// COMMAND INJECTION
// ==========================================

function commandInjection(userInput) {
    // Command injection via exec
    exec('ls ' + userInput, (error, stdout) => {
        console.log(stdout);
    });

    // Command injection via eval
    eval(userInput);

    // Command injection via Function constructor
    const fn = new Function(userInput);
    fn();
}

// ==========================================
// WEAK CRYPTOGRAPHY
// ==========================================

function weakCrypto() {
    // MD5 - weak hash
    const hash = crypto.createHash('md5');
    hash.update('password');
    console.log(hash.digest('hex'));

    // SHA1 - weak hash
    const sha1 = crypto.createHash('sha1');
    sha1.update('secret');

    // DES - weak cipher
    const cipher = crypto.createCipher('des', 'key');

    // Hardcoded secret
    const secret = "hardcoded-secret-key-12345";
    const token = jwt.sign({ user: 'admin' }, secret);
}

// ==========================================
// PATH TRAVERSAL
// ==========================================

app.get('/download', (req, res) => {
    const filename = req.query.file;

    // Path traversal vulnerability
    const filepath = '/uploads/' + filename;
    res.sendFile(filepath);

    // Path traversal with fs.readFile
    fs.readFile('./files/' + filename, (err, data) => {
        res.send(data);
    });
});

// ==========================================
// INSECURE RANDOM
// ==========================================

function insecureRandom() {
    // Math.random() for security-sensitive operations
    const token = Math.random().toString(36);
    const sessionId = Math.floor(Math.random() * 1000000);

    return token;
}

// ==========================================
// REGEX DOS (ReDoS)
// ==========================================

function regexDos(userInput) {
    // Catastrophic backtracking
    const regex = /^(a+)+$/;
    const match = userInput.match(regex);

    // Another vulnerable regex
    const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
    return emailRegex.test(userInput);
}

// ==========================================
// INSECURE DESERIALIZATION
// ==========================================

function insecureDeserialization(userInput) {
    // Unsafe JSON parse
    const obj = JSON.parse(userInput);

    // Eval-based deserialization
    const data = eval('(' + userInput + ')');

    return obj;
}

// ==========================================
// MISSING INPUT VALIDATION
// ==========================================

app.post('/user', (req, res) => {
    const user = req.body;

    // No input validation
    const db = mysql.createConnection({});
    db.query('INSERT INTO users SET ?', user);

    res.json({ success: true });
});

// ==========================================
// INSECURE COOKIE CONFIGURATION
// ==========================================

app.get('/login', (req, res) => {
    // Missing httpOnly flag
    res.cookie('session', 'abc123', {
        secure: false,  // Not secure
        httpOnly: false  // Vulnerable to XSS
    });

    // Missing SameSite
    res.cookie('token', 'xyz789');
});

// ==========================================
// CORS MISCONFIGURATION
// ==========================================

app.use((req, res, next) => {
    // Overly permissive CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// ==========================================
// PROTOTYPE POLLUTION
// ==========================================

function prototypePollution(userInput) {
    const obj = {};

    // Prototype pollution via merge
    Object.assign(obj, JSON.parse(userInput));

    // Unsafe property assignment
    const key = userInput.key;
    obj[key] = userInput.value;
}

// ==========================================
// OPEN REDIRECT
// ==========================================

app.get('/redirect', (req, res) => {
    const url = req.query.url;

    // Open redirect vulnerability
    res.redirect(url);

    // Another open redirect
    res.redirect(301, req.query.next);
});

// ==========================================
// INFORMATION DISCLOSURE
// ==========================================

app.use((err, req, res, next) => {
    // Exposing stack traces
    res.status(500).json({
        error: err.message,
        stack: err.stack  // Information disclosure
    });
});

// ==========================================
// MISSING RATE LIMITING
// ==========================================

app.post('/api/login', (req, res) => {
    // No rate limiting - brute force vulnerability
    const { username, password } = req.body;

    if (username === 'admin' && password === 'password') {
        res.json({ token: 'abc123' });
    }
});

// ==========================================
// INSECURE DIRECT OBJECT REFERENCE (IDOR)
// ==========================================

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;

    // No authorization check - IDOR
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, user) => {
        res.json(user);
    });
});

// ==========================================
// HARDCODED CREDENTIALS
// ==========================================

const DATABASE_PASSWORD = "admin123";  // Hardcoded password
const API_KEY = "sk_live_1234567890abcdef";  // Hardcoded API key
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // Hardcoded AWS secret

// ==========================================
// UNSAFE REGEX
// ==========================================

function unsafeRegex(input) {
    // Unsafe regex with user input
    const pattern = new RegExp(input);
    return pattern.test('test');
}

// ==========================================
// NULL BYTE INJECTION
// ==========================================

app.get('/file', (req, res) => {
    const filename = req.query.name;

    // Null byte injection
    fs.readFile(filename + '.txt', (err, data) => {
        res.send(data);
    });
});

// ==========================================
// MISSING AUTHENTICATION
// ==========================================

app.get('/admin/users', (req, res) => {
    // No authentication check
    const users = db.query('SELECT * FROM users');
    res.json(users);
});

// ==========================================
// INSECURE HTTP
// ==========================================

const http = require('http');

// HTTP instead of HTTPS
http.createServer(app).listen(3000);

console.log("Vulnerable JavaScript application for testing");
console.log("DO NOT use in production!");
