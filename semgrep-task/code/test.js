
// ==========================================
// BAD PRACTICE 1: Single-letter variables
// ==========================================
let a = 5;
let b = 10;
let x = "test";

// ==========================================
// BAD PRACTICE 2: Using == instead of ===
// ==========================================
if (a == "5") {
    console.log("Loose equality used");
}

if (b != 10) {
    console.log("Loose inequality used");
}

// ==========================================
// BAD PRACTICE 3: Console.log in production
// ==========================================
console.log("This is a debug message");
console.debug("Debugging information");

// ==========================================
// BAD PRACTICE 4: Using let instead of const
// ==========================================
let userName = "John Doe";
let maxLimit = 100;

// ==========================================
// BAD PRACTICE 5: Empty catch blocks
// ==========================================
try {
    riskyOperation();
} catch (error) {
    // Empty catch block - ignoring errors
}

try {
    anotherRiskyOperation();
} catch (e) {
}

// ==========================================
// BAD PRACTICE 6: Hard-coded credentials
// ==========================================
const password = "admin123";
const badApiKey = "sk-1234567890abcdef";
let badDbPassword = "secretPassword";

// ==========================================
// BAD PRACTICE 7: Magic numbers
// ==========================================
if (age > 18) {
    console.log("Adult");
}

if (score > 75) {
    console.log("Pass");
}

// ==========================================
// BAD PRACTICE 8: SQL Injection vulnerability
// ==========================================
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    database.execute(query);
}

function searchUsers(searchTerm) {
    database.query("SELECT * FROM users WHERE name = '" + searchTerm + "'");
}

// ==========================================
// BAD PRACTICE 9: Using eval()
// ==========================================
function calculateExpression(expression) {
    return eval(expression);
}

// ==========================================
// BAD PRACTICE 10: Duplicate code (DRY violation)
// ==========================================
if (userAge > 18) {
    grantAccess();
}

// ... some other code ...

if (userAge > 18) {
    grantAccess();
}

// ==========================================
// BAD PRACTICE 11: Long function (too many responsibilities)
// ==========================================
function processUser() {
    validateUserInput();
    checkUserPermissions();
    saveUserToDatabase();
    sendWelcomeEmail();
    logUserActivity();
    updateUserStatistics();
    notifyAdministrators();
    generateUserReport();
    archiveOldData();
    cleanupTempFiles();
}

// ==========================================
// BAD PRACTICE 12: Missing input validation
// ==========================================
function saveUserAge(age) {
    database.save(age);
}

// ==========================================
// BAD PRACTICE 13: Inefficient array operations
// ==========================================
let badResults = [];
for (let i = 0; i < items.length; i++) {
    badResults.push(items[i] * 2);
}

// ==========================================
// BAD PRACTICE 14: Unclear variable names
// ==========================================
let amt = 1000;
let qty = 5;
let tmp = calculateTotal();

// ==========================================
// BAD PRACTICE 15: Multiple statements per line
// ==========================================
let count = 0; let total = 0; let average = 0;

// ==========================================
// GOOD PRACTICES (for comparison)
// ==========================================

// GOOD: Meaningful variable names
const totalAmount = 1000;
const itemQuantity = 5;

// GOOD: Strict equality
if (totalAmount === 1000) {
    console.log("Correct amount");
}

// GOOD: Proper error handling
try {
    performOperation();
} catch (error) {
    logger.error("Operation failed", error);
    throw new Error("Failed to perform operation");
}

// GOOD: Using constants instead of magic numbers
const VOTING_AGE = 18;
const PASSING_SCORE = 75;

if (userAge >= VOTING_AGE) {
    console.log("Eligible to vote");
}

// GOOD: Environment variables for sensitive data
const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;

// GOOD: Parameterized queries
function getUserDataSecure(userId) {
    const query = "SELECT * FROM users WHERE id = ?";
    database.execute(query, [userId]);
}

// GOOD: Input validation
function saveUserAgeSecure(age) {
    if (age > 0 && age < 120) {
        database.save(age);
    } else {
        throw new Error("Invalid age value");
    }
}

// GOOD: Single Responsibility Principle
function validateUser() {
    // Only validation logic
}

function saveUser() {
    // Only save logic
}

function sendEmail() {
    // Only email logic
}

// GOOD: Using array methods instead of loops
const results = items.map(item => item * 2);
const filtered = items.filter(item => item > 10);

// GOOD: Using const for immutable values
const MAX_RETRY_COUNT = 3;
const API_ENDPOINT = "https://api.example.com";

// Helper functions (referenced above)
function riskyOperation() { }
function anotherRiskyOperation() { }
function grantAccess() { }
function validateUserInput() { }
function checkUserPermissions() { }
function saveUserToDatabase() { }
function sendWelcomeEmail() { }
function logUserActivity() { }
function updateUserStatistics() { }
function notifyAdministrators() { }
function generateUserReport() { }
function archiveOldData() { }
function cleanupTempFiles() { }
function calculateTotal() { return 0; }
function performOperation() { }

// Mock objects
const database = {
    execute: () => { },
    query: () => { },
    save: () => { }
};

const logger = {
    error: () => { }
};

// Variables referenced
let age = 20;
let score = 80;
let userId = 1;
let userAge = 25;
let items = [1, 2, 3, 4, 5];