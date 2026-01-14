import axios from 'axios';

const API_BASE_URL = '/api';

const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

/**
 * Create a new scan
 * @param {object} scanData - Scan configuration
 * @param {string} scanData.type - 'github' or 'upload'
 * @param {string} scanData.url - GitHub URL (if type is 'github')
 * @param {File} scanData.file - ZIP file (if type is 'upload')
 */
export const createScan = async (scanData) => {
    try {
        if (scanData.type === 'github') {
            const response = await apiClient.post('/scan', {
                type: 'github',
                url: scanData.url
            });
            return response.data;
        } else {
            // Upload file
            const formData = new FormData();
            formData.append('file', scanData.file);
            formData.append('type', 'upload');

            const response = await apiClient.post('/scan', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });
            return response.data;
        }
    } catch (error) {
        console.error('Create scan error:', error);
        throw error;
    }
};

/**
 * Get all scans
 */
export const getScans = async () => {
    try {
        const response = await apiClient.get('/scans');
        return response.data;
    } catch (error) {
        console.error('Get scans error:', error);
        throw error;
    }
};

/**
 * Get specific scan by ID
 */
export const getScan = async (scanId) => {
    try {
        const response = await apiClient.get(`/scans/${scanId}`);
        return response.data;
    } catch (error) {
        console.error('Get scan error:', error);
        throw error;
    }
};

/**
 * Download report for a scan
 * @param {string} scanId - Scan ID
 * @param {number} index - Report index (optional, defaults to 0)
 * @param {string} filename - Filename for download (optional)
 */
export const downloadReport = async (scanId, index = 0, filename = null) => {
    try {
        const url = index !== undefined ? `/reports/${scanId}/${index}` : `/reports/${scanId}`;
        const response = await apiClient.get(url, {
            responseType: 'blob'
        });

        // Create download link
        const blob = new Blob([response.data]);
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.setAttribute('download', filename || `report_${scanId}_${index}.xlsx`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(downloadUrl);

        return { success: true };
    } catch (error) {
        console.error('Download report error:', error);
        throw error;
    }
};

/**
 * Generate a new Semgrep rule using AI
 * @param {object} ruleData - Rule configuration
 */
export const generateRule = async (ruleData) => {
    try {
        const response = await apiClient.post('/rules/generate', ruleData);
        return response.data;
    } catch (error) {
        console.error('Generate rule error:', error);
        throw error;
    }
};

export default {
    createScan,
    getScans,
    getScan,
    downloadReport,
    generateRule
};
