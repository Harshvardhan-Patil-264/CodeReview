/**
 * Input validation middleware
 * Validates GitHub URLs and file uploads
 */

const GITHUB_URL_REGEX = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/i;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

/**
 * Validate GitHub URL format
 */
function validateGitHubUrl(url) {
    if (!url || typeof url !== 'string') {
        return { valid: false, error: 'GitHub URL is required and must be a string' };
    }

    if (!GITHUB_URL_REGEX.test(url.trim())) {
        return {
            valid: false,
            error: 'Invalid GitHub URL format. Expected: https://github.com/username/repository'
        };
    }

    return { valid: true };
}

/**
 * Validate file upload
 */
function validateFileUpload(file) {
    if (!file) {
        return { valid: false, error: 'No file uploaded' };
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
        return {
            valid: false,
            error: `File size exceeds maximum allowed size of ${MAX_FILE_SIZE / 1024 / 1024}MB`
        };
    }

    // Check file type (must be ZIP)
    const allowedMimeTypes = [
        'application/zip',
        'application/x-zip-compressed',
        'multipart/x-zip'
    ];

    const fileExtension = file.originalname.split('.').pop().toLowerCase();

    if (!allowedMimeTypes.includes(file.mimetype) && fileExtension !== 'zip') {
        return {
            valid: false,
            error: 'Only ZIP files are allowed'
        };
    }

    return { valid: true };
}

/**
 * Sanitize path to prevent directory traversal
 */
function sanitizePath(inputPath) {
    // Remove any attempts at directory traversal
    const sanitized = inputPath.replace(/\.\./g, '').replace(/[<>:"|?*]/g, '');
    return sanitized;
}

module.exports = {
    validateGitHubUrl,
    validateFileUpload,
    sanitizePath
};
