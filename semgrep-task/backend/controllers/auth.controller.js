const User = require('../models/User');
const jwt = require('jsonwebtoken');

/**
 * Generate JWT token
 */
const generateToken = (userId) => {
    return jwt.sign(
        { userId },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
};

/**
 * POST /api/auth/register
 * Register new user with email and password
 */
exports.register = async (req, res, next) => {
    try {
        const { email, username, password } = req.body;

        // Validation
        if (!email || !username || !password) {
            const error = new Error('Email, username, and password are required');
            error.status = 400;
            error.code = 'MISSING_FIELDS';
            throw error;
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            where: {
                [require('sequelize').Op.or]: [{ email }, { username }],
            },
        });

        if (existingUser) {
            const error = new Error(
                existingUser.email === email
                    ? 'Email already registered'
                    : 'Username already taken'
            );
            error.status = 409;
            error.code = 'USER_EXISTS';
            throw error;
        }

        // Create user
        const user = await User.create({
            email,
            username,
            password,
            authProvider: 'local',
        });

        // Generate token
        const token = generateToken(user.id);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: user.toJSON(),
        });
    } catch (error) {
        next(error);
    }
};

/**
 * POST /api/auth/login
 * Login with email/username and password
 */
exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            const error = new Error('Email and password are required');
            error.status = 400;
            error.code = 'MISSING_FIELDS';
            throw error;
        }

        // Find user by email or username
        const user = await User.findOne({
            where: {
                [require('sequelize').Op.or]: [{ email }, { username: email }],
            },
        });

        if (!user) {
            const error = new Error('Invalid credentials');
            error.status = 401;
            error.code = 'INVALID_CREDENTIALS';
            throw error;
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);

        if (!isPasswordValid) {
            const error = new Error('Invalid credentials');
            error.status = 401;
            error.code = 'INVALID_CREDENTIALS';
            throw error;
        }

        // Generate token
        const token = generateToken(user.id);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: user.toJSON(),
        });
    } catch (error) {
        next(error);
    }
};

/**
 * POST /api/auth/logout
 * Logout user (JWT is stateless, client handles token removal)
 */
exports.logout = async (req, res, next) => {
    try {
        res.json({
            success: true,
            message: 'Logged out successfully',
        });
    } catch (error) {
        next(error);
    }
};

/**
 * GET /api/auth/me
 * Get current logged-in user
 */
exports.getCurrentUser = async (req, res, next) => {
    try {
        // req.user is set by authenticateToken middleware
        res.json({
            success: true,
            user: req.user.toJSON(),
        });
    } catch (error) {
        next(error);
    }
};
