/**
 * Purpose: Example file demonstrating proper coding standards with mandatory file header
 * Author: John Doe
 * Date: 2025-12-16
 * Modified By: Jane Smith - 2025-12-16 - Added input validation examples
 */

// ==========================================
// GOOD PRACTICES DEMONSTRATION
// ==========================================

// GOOD: Using const for immutable values
const VOTING_AGE = 18;
const PASSING_SCORE = 75;
const MAX_RETRY_COUNT = 3;
const API_ENDPOINT = process.env.API_ENDPOINT || "https://api.example.com";

// GOOD: Meaningful variable names
const totalAmount = 1000;
const itemQuantity = 5;
const userAge = 25;

// GOOD: Strict equality
if (totalAmount === 1000) {
    logger.info("Correct amount");
}

// GOOD: Proper error handling
try {
    performOperation();
} catch (error) {
    logger.error("Operation failed", error);
    throw new Error("Failed to perform operation: " + error.message);
}

// GOOD: Environment variables for sensitive data
const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;

// GOOD: Using constants instead of magic numbers
if (userAge >= VOTING_AGE) {
    logger.info("Eligible to vote");
}

// GOOD: Parameterized queries to prevent SQL injection
function getUserDataSecure(userId) {
    const query = "SELECT * FROM users WHERE id = ?";
    return database.execute(query, [userId]);
}

// GOOD: Input validation
function saveUserAgeSecure(age) {
    if (typeof age !== 'number') {
        throw new TypeError("Age must be a number");
    }

    if (age <= 0 || age >= 120) {
        throw new RangeError("Age must be between 1 and 119");
    }

    return database.save({ age });
}

// GOOD: Single Responsibility Principle
function validateUser(userData) {
    if (!userData.email || !userData.name) {
        throw new Error("Missing required fields");
    }
    return true;
}

function saveUser(userData) {
    return database.users.insert(userData);
}

function sendWelcomeEmail(userEmail) {
    return emailService.send({
        to: userEmail,
        subject: "Welcome!",
        template: "welcome"
    });
}

// GOOD: Using array methods instead of loops
const items = [1, 2, 3, 4, 5];
const doubledItems = items.map(item => item * 2);
const filteredItems = items.filter(item => item > 2);
const sum = items.reduce((acc, item) => acc + item, 0);

// GOOD: Proper function documentation
/**
 * Calculates the total price including tax
 * @param {number} price - Base price before tax
 * @param {number} taxRate - Tax rate as decimal (e.g., 0.18 for 18%)
 * @returns {number} Total price with tax applied
 */
function calculateTotalPrice(price, taxRate) {
    if (typeof price !== 'number' || typeof taxRate !== 'number') {
        throw new TypeError("Price and tax rate must be numbers");
    }

    return price * (1 + taxRate);
}

// GOOD: Using descriptive names for complex conditions
const isAdult = userAge >= VOTING_AGE;
const hasPassedExam = score >= PASSING_SCORE;
const isEligibleForCertificate = isAdult && hasPassedExam;

if (isEligibleForCertificate) {
    issueCertificate();
}

// Mock implementations
const database = {
    execute: (query, params) => Promise.resolve([]),
    save: (data) => Promise.resolve(data),
    users: {
        insert: (data) => Promise.resolve({ id: 1, ...data })
    }
};

const logger = {
    info: (msg) => console.log(`[INFO] ${msg}`),
    error: (msg, err) => console.error(`[ERROR] ${msg}`, err)
};

const emailService = {
    send: (options) => Promise.resolve({ sent: true })
};

function performOperation() {
    return true;
}

function issueCertificate() {
    logger.info("Certificate issued");
}

let score = 80;
