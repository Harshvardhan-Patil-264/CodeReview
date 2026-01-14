const fs = require('fs');
const path = require('path');

/**
 * Structured logging middleware
 * Logs all requests with timestamp, request ID, method, path, and IP
 */
function logger(req, res, next) {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    req.requestId = requestId;

    const logEntry = {
        timestamp: new Date().toISOString(),
        requestId: requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent') || 'unknown'
    };

    // Log to console
    console.log(`[${logEntry.timestamp}] ${logEntry.method} ${logEntry.path} - ${requestId}`);

    // Log to file
    const logDir = path.join(__dirname, '..', 'logs');
    const logFile = path.join(logDir, `${new Date().toISOString().split('T')[0]}.log`);

    fs.appendFile(logFile, JSON.stringify(logEntry) + '\n', (err) => {
        if (err) console.error('Failed to write to log file:', err);
    });

    next();
}

module.exports = logger;
