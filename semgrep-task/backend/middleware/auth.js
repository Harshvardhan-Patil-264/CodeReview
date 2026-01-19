const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Middleware to verify JWT token and attach user to request
 */
const authenticateToken = async (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                success: false,
                error: {
                    message: 'Access token required',
                    code: 'NO_TOKEN',
                },
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Get user from database
        const user = await User.findByPk(decoded.userId);

        if (!user) {
            return res.status(401).json({
                success: false,
                error: {
                    message: 'Invalid token',
                    code: 'INVALID_TOKEN',
                },
            });
        }

        // Attach user to request
        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: {
                    message: 'Invalid token',
                    code: 'INVALID_TOKEN',
                },
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: {
                    message: 'Token expired',
                    code: 'TOKEN_EXPIRED',
                },
            });
        }

        console.error('Auth middleware error:', error);
        return res.status(500).json({
            success: false,
            error: {
                message: 'Authentication failed',
                code: 'AUTH_ERROR',
            },
        });
    }
};

module.exports = { authenticateToken };
