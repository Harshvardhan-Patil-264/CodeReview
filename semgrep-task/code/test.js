/*
 * Purpose: Comprehensive test file for JavaScript coding rules - demonstrates all 20 rules
 * Author: Harsh Patil
 * Date: 2025-12-18
 * Modified By: N/A
 */

// ==========================================
// RULE 1: Use Strict Equality
// Why: Prevents unexpected type coercion
// ==========================================

// BAD: Using loose equality (==)
if (value == 0) {
    console.log("This will match 0, '0', false, '', etc.");
}

if (count != 10) {
    console.log("Loose inequality");
}

const isEqual = (x == y);

// GOOD: Using strict equality (===)
if (value === 0) {
    handleZero();
}

if (count !== 10) {
    handleNonTen();
}

const isStrictEqual = (x === y);

// ==========================================
// RULE 2: Use const or let (Never var)
// Why: Avoids scope and hoisting issues
// ==========================================

// BAD: Using var
var oldStyleVariable = 10;
var userName = "John";
var isActive = true;

// GOOD: Using const or let
const maxLimit = 10;
let currentCount = 0;
const isUserActive = true;

// ==========================================
// RULE 3: Prefer const Over let
// Why: Prevents accidental reassignment
// ==========================================

// BAD: Using let for values that don't change
let apiUrl = "https://api.example.com";
let maxRetries = 3;
let configValue = "production";

// GOOD: Using const
const API_URL = "https://api.example.com";
const MAX_RETRIES_GOOD = 3;
const CONFIG_VALUE = "production";

// GOOD: Using let when reassignment is needed
let counter = 0;
counter++;

// ==========================================
// RULE 4: Use Meaningful Variable Names
// Why: Improves readability and understanding
// ==========================================

// BAD: Single-letter or unclear names
const a = 25;
const b = "test";
const xBad = getUserData();
let t = Date.now();

// GOOD: Meaningful names
const userAge = 25;
const testMessage = "test";
const userDataGood = getUserData();
let timestamp = Date.now();

// Exception: Loop counters can be single letters
for (let i = 0; i < 10; i++) {
    console.log(i);
}

// ==========================================
// RULE 5: Always Handle Errors
// Why: Prevents silent failures and crashes
// ==========================================

// BAD: Empty catch blocks
try {
    saveData();
} catch (error) {
    // Empty - ignoring errors
}

try {
    processPayment();
} catch (e) {
}

// GOOD: Proper error handling
try {
    saveData();
} catch (error) {
    logger.error("Failed to save data:", error);
    throw new Error("Data save operation failed");
}

try {
    processPayment();
} catch (error) {
    logger.error("Payment processing failed:", error);
    notifyUser("Payment failed. Please try again.");
}

// ==========================================
// RULE 6: Handle Promises Properly
// Why: Avoids unhandled promise rejections
// ==========================================

// BAD: Promise without catch
fetchData().then(handleResponse);

getUserInfo().then(processUser);

// GOOD: Promise with catch
fetchData()
    .then(handleResponse)
    .catch(handleError);

getUserInfo()
    .then(processUser)
    .catch(error => {
        logger.error("Failed to get user info:", error);
    });

// ==========================================
// RULE 7: Prefer async/await
// Why: Improves readability and control flow
// ==========================================

// BAD: Promise chains
getUser().then(user => getProfile(user.id)).then(profile => displayProfile(profile));

// GOOD: async/await
async function loadUserProfile() {
    const user = await getUser();
    const profile = await getProfile(user.id);
    displayProfile(profile);
}

// ==========================================
// RULE 8: Avoid console.log in Production
// Why: Prevents leaking sensitive information
// ==========================================

// BAD: Using console statements
console.log("User data:", userData);
console.debug("Debug info:", debugInfo);
console.info("Information:", info);
console.warn("Warning:", warning);

// GOOD: Using proper logging library
logger.info("User successfully logged in", { userId: user.id });
logger.debug("Debug information", { debugInfo });
logger.warn("Warning message", { warning });

// ==========================================
// RULE 9: Avoid Magic Numbers
// Why: Makes code easier to understand and modify
// ==========================================

// BAD: Magic numbers
if (retryCount > 3) {
    stopRetry();
}

if (age < 18) {
    denyAccess();
}

if (score >= 75) {
    markAsPassed();
}

// GOOD: Named constants
const MAX_RETRIES_EXAMPLE = 3;
const MINIMUM_AGE = 18;
const PASSING_SCORE = 75;

if (retryCount > MAX_RETRIES_EXAMPLE) {
    stopRetry();
}

if (age < MINIMUM_AGE) {
    denyAccess();
}

if (score >= PASSING_SCORE) {
    markAsPassed();
}

// ==========================================
// RULE 10: Validate Inputs
// Why: Prevents runtime and security issues
// ==========================================

// BAD: No input validation
function saveUserData(user) {
    database.save(user);
}

function processOrder(order) {
    database.save(order);
}

// GOOD: Input validation
function saveUserDataSecure(user) {
    if (!user || !user.id) {
        throw new Error("Invalid user input");
    }

    if (typeof user.email !== 'string' || !user.email.includes('@')) {
        throw new Error("Invalid email format");
    }

    database.save(user);
}

function processOrderSecure(order) {
    if (!order || !order.items || order.items.length === 0) {
        throw new Error("Invalid order: no items");
    }

    if (order.total <= 0) {
        throw new Error("Invalid order total");
    }

    database.save(order);
}

// ==========================================
// RULE 11: Do Not Modify Function Parameters
// Why: Avoids unexpected side effects
// ==========================================

// BAD: Modifying parameters
function activateUser(user) {
    user.active = true;
    user.activatedAt = Date.now();
    return user;
}

function updateConfig(config) {
    config = { ...config, updated: true };
    return config;
}

// GOOD: Return new objects
function activateUserSafe(user) {
    return {
        ...user,
        active: true,
        activatedAt: Date.now()
    };
}

function updateConfigSafe(config) {
    return {
        ...config,
        updated: true
    };
}

// ==========================================
// RULE 12: Avoid eval()
// Why: Prevents security vulnerabilities
// ==========================================

// BAD: Using eval()
function calculateExpression(expression) {
    return eval(expression);
}

const result = eval("2 + 2");

// GOOD: Use safe alternatives
function calculateExpressionSafe(a, b, operator) {
    switch (operator) {
        case '+': return a + b;
        case '-': return a - b;
        case '*': return a * b;
        case '/': return a / b;
        default: throw new Error("Invalid operator");
    }
}

const parsedData = JSON.parse(jsonString);

// ==========================================
// RULE 13: Avoid innerHTML with User Data
// Why: Prevents XSS attacks
// ==========================================

// BAD: Using innerHTML with user input
const userInput = getUserInput();
element.innerHTML = userInput;
element.outerHTML = userInput;

// GOOD: Use textContent or sanitize
element.textContent = userInput;

// Or use a sanitization library
const sanitizedInput = DOMPurify.sanitize(userInput);
element.innerHTML = sanitizedInput;

// ==========================================
// RULE 14: Always Specify Radix in parseInt
// Why: Ensures consistent number parsing
// ==========================================

// BAD: No radix specified
const countBad = parseInt(value);
const numberBad = parseInt("08");

// GOOD: Radix specified
const countSafe = parseInt(value, 10);
const numberSafe = parseInt("08", 10);
const hexValue = parseInt("FF", 16);

// ==========================================
// RULE 15: Avoid async inside forEach
// Why: forEach does not wait for async operations
// ==========================================

// BAD: async in forEach
items.forEach(async (item) => {
    await processItem(item);
    await saveItem(item);
});

users.forEach(async (user) => {
    await sendEmail(user);
});

// GOOD: Use for...of or Promise.all
async function processItemsCorrectly() {
    for (const item of items) {
        await processItem(item);
        await saveItem(item);
    }

    await Promise.all(users.map(async (user) => {
        await sendEmail(user);
    }));
}

// ==========================================
// RULE 16: Avoid Floating Promises
// Why: Ensures errors are handled
// ==========================================

// BAD: Floating promises
saveData();
processPayment();
sendNotification();

// GOOD: Await or handle promises
async function handlePromisesCorrectly() {
    await saveData();
    await processPayment();
    await sendNotification();
}

// Or with error handling
saveData().catch(error => logger.error("Save failed:", error));

// ==========================================
// RULE 17: Do Not Hard-Code Secrets
// Why: Protects sensitive data
// ==========================================

// BAD: Hard-coded secrets
const password = "admin123";
const apiKey = "sk-1234567890abcdef";
const secret = "my-secret-key";
const token = "ghp_1234567890";

// GOOD: Use environment variables
const dbPassword = process.env.DB_PASSWORD;
const apiKeySecure = process.env.API_KEY;
const jwtSecret = process.env.JWT_SECRET;
const githubToken = process.env.GITHUB_TOKEN;

// ==========================================
// RULE 18: Use Default Parameters
// Why: Handles falsy values correctly
// ==========================================

// BAD: Manual default value checks
function log(level) {
    if (!level) {
        level = "info";
    }
    writeLog(level);
}

function createUser(name) {
    if (!name) {
        name = "Anonymous";
    }
    return { name };
}

// GOOD: Default parameters
function logSafe(level = "info") {
    writeLog(level);
}

function createUserSafe(name = "Anonymous") {
    return { name };
}

// ==========================================
// RULE 19: Reduce Nested Code
// Why: Improves readability
// ==========================================

// BAD: Deeply nested code
if (user) {
    if (user.isActive) {
        if (user.hasPermission) {
            processUser(user);
        }
    }
}

// GOOD: Early returns
if (!user) return;
if (!user.isActive) return;
if (!user.hasPermission) return;

processUser(user);

// ==========================================
// RULE 20: One Function Should Do One Thing
// Why: Simplifies testing and maintenance
// ==========================================

// BAD: Function doing too many things
function processUserRegistration() {
    validateInput();
    checkDuplicateEmail();
    hashPassword();
    saveToDatabase();
    sendWelcomeEmail();
    logActivity();
    updateStatistics();
    notifyAdmins();
    createUserProfile();
    assignDefaultRole();
    generateApiKey();
    sendSlackNotification();
}

// GOOD: Single responsibility
function calculateTotal(items) {
    return items.reduce((sum, item) => sum + item.price, 0);
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function formatDate(date) {
    return new Date(date).toISOString();
}

// ==========================================
// HELPER FUNCTIONS (for testing)
// ==========================================
function handleZero() { }
function handleNonTen() { }
function getUserData() { return {}; }
function saveData() { }
function processPayment() { }
function handleResponse() { }
function handleError() { }
function fetchData() { return Promise.resolve(); }
function getUserInfo() { return Promise.resolve(); }
function processUser() { }
function getUser() { return Promise.resolve({ id: 1 }); }
function getProfile(id) { return Promise.resolve({}); }
function displayProfile() { }
function stopRetry() { }
function denyAccess() { }
function markAsPassed() { }
function processItem() { }
function saveItem() { }
function sendEmail() { }
function sendNotification() { }
function writeLog() { }
function notifyUser() { }
function getUserInput() { return ""; }
function validateInput() { }
function checkDuplicateEmail() { }
function hashPassword() { }
function saveToDatabase() { }
function sendWelcomeEmail() { }
function logActivity() { }
function updateStatistics() { }
function notifyAdmins() { }
function createUserProfile() { }
function assignDefaultRole() { }
function generateApiKey() { }
function sendSlackNotification() { }

// Mock objects
const logger = {
    info: () => { },
    debug: () => { },
    warn: () => { },
    error: () => { }
};

const database = {
    save: () => { }
};

const element = {
    innerHTML: "",
    outerHTML: "",
    textContent: ""
};

const DOMPurify = {
    sanitize: (input) => input
};

// Variables
let value = 0;
let count = 10;
let x = 1;
let y = 2;
let userData = {};
let debugInfo = {};
let info = {};
let warning = {};
let user = { id: 1, isActive: true, hasPermission: true };
let retryCount = 0;
let age = 20;
let score = 80;
let items = [{ price: 10 }, { price: 20 }];
let users = [{ email: "test@example.com" }];
let jsonString = '{"key": "value"}';