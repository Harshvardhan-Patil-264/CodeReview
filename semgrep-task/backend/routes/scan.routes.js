const express = require('express');
const multer = require('multer');
const path = require('path');
const scanController = require('../controllers/scan.controller');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '..', 'uploads'));
    },
    filename: (req, file, cb) => {
        cb(null, `upload_${Date.now()}_${file.originalname}`);
    }
});

const upload = multer({ storage: storage });

// All scan routes require authentication
router.post('/scan', authenticateToken, upload.single('file'), scanController.createScan);
router.get('/scans', authenticateToken, scanController.getScans);
router.get('/scans/:id', authenticateToken, scanController.getScan);
router.get('/scans/:id/reports/:index', authenticateToken, scanController.getReportByIndex);

module.exports = router;
