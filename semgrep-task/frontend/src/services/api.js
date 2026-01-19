import axios from 'axios';

// Get API base URL from environment or default to localhost
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

// Create axios instance
const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor - automatically attach JWT token
apiClient.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor - handle token expiry and unauthorized access
apiClient.interceptors.response.use(
    (response) => {
        return response;
    },
    (error) => {
        // Handle 401 errors (unauthorized/expired token)
        if (error.response && error.response.status === 401) {
            // Clear local storage
            localStorage.removeItem('token');
            localStorage.removeItem('user');

            // Redirect to login only if not already on auth pages
            const currentPath = window.location.pathname;
            if (currentPath !== '/login' && currentPath !== '/signup') {
                window.location.href = '/login';
            }
        }
        return Promise.reject(error);
    }
);

// ==================== SCAN APIs ====================

export const scanAPI = {
    /**
     * Create a new scan
     */
    createScan: async (formData) => {
        const response = await apiClient.post('/api/scan', formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        });
        return response.data;
    },

    /**
     * Get all scans
     */
    getAllScans: async () => {
        const response = await apiClient.get('/api/scans');
        return response.data;
    },

    /**
     * Get scan by ID
     */
    getScanById: async (scanId) => {
        const response = await apiClient.get(`/api/scans/${scanId}`);
        return response.data;
    },

    /**
     * Download report
     */
    downloadReport: async (scanId, reportIndex = 0) => {
        const response = await apiClient.get(`/api/reports/${scanId}/${reportIndex}`, {
            responseType: 'blob',
        });

        // Create download link
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `report_${scanId}_${reportIndex}.xlsx`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);

        return { success: true };
    },

    /**
     * Download report by index (matches backend /api/scans/:id/reports/:index route)
     */
    downloadReportByIndex: async (scanId, reportIndex = 0) => {
        const response = await apiClient.get(`/api/scans/${scanId}/reports/${reportIndex}`, {
            responseType: 'blob',
        });

        // Return the blob directly for the component to handle
        return response.data;
    },
};

// ==================== AUTH APIs ====================

export const authAPI = {
    /**
     * Register a new user
     */
    register: async (userData) => {
        const response = await apiClient.post('/api/auth/register', userData);
        // Store token in localStorage
        if (response.data.token) {
            localStorage.setItem('token', response.data.token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
        }
        return response.data;
    },

    /**
     * Login with email/username and password
     */
    login: async (credentials) => {
        const response = await apiClient.post('/api/auth/login', credentials);
        // Store token in locals torage
        if (response.data.token) {
            localStorage.setItem('token', response.data.token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
        }
        return response.data;
    },

    /**
     * Get current logged-in user
     */
    getCurrentUser: async () => {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('No token found');

        const response = await apiClient.get('/api/auth/me', {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });
        return response.data;
    },

    /**
     * Logout user
     */
    logout: () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    },

    /**
     * Check if user is logged in
     */
    isAuthenticated: () => {
        return !!localStorage.getItem('token');
    },

    /**
     * Get stored user data
     */
    getStoredUser: () => {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },
};

// ==================== RULE APIs ====================

export const ruleAPI = {
    /**
     * Generate a new Semgrep rule using AI
     */
    generateRule: async (data) => {
        const response = await apiClient.post('/api/rules/generate', data);
        return response.data;
    },

    /**
     * Preview a rule without saving
     */
    previewRule: async (data) => {
        const response = await apiClient.post('/api/rules/preview', data);
        return response.data;
    },

    /**
     * Confirm and save a previewed rule
     */
    confirmRule: async (rule, language) => {
        const response = await apiClient.post('/api/rules/confirm', {
            rule,
            language,
        });
        return response.data;
    },

    /**
     * Validate a rule description (garbage detection)
     */
    validateDescription: async (description) => {
        const response = await apiClient.post('/api/rules/validate', {
            description,
        });
        return response.data;
    },
};

// Export the axios instance for custom requests
export default apiClient;
