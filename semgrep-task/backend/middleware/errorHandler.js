/**
 * Centralized error handling middleware
 * Returns consistent error response format
 */
function errorHandler(err, req, res, next) {
    const timestamp = new Date().toISOString();
    const requestId = req.requestId || 'unknown';

    // Determine if this is a user error or system error
    const isUserError = err.status && err.status < 500;
    const statusCode = err.status || 500;

    const errorResponse = {
        success: false,
        error: {
            message: isUserError ? err.message : 'Internal server error',
            code: err.code || 'INTERNAL_ERROR',
            requestId: requestId,
            timestamp: timestamp
        }
    };

    // Log error details
    console.error(`[${timestamp}] ERROR - ${requestId}:`, {
        status: statusCode,
        message: err.message,
        stack: err.stack
    });

    // Include stack trace in development
    if (process.env.NODE_ENV !== 'production') {
        errorResponse.error.stack = err.stack;
    }

    res.status(statusCode).json(errorResponse);
}

module.exports = errorHandler;
