const express = require('express');
const multer = require('multer');
const path = require('path');
const scanController = require('../controllers/scan.controller');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '..', 'uploads');
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `upload_${Date.now()}_${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    }
});

// Routes
router.post('/scan', upload.single('file'), scanController.createScan);
router.get('/scans', scanController.getScans);
router.get('/scans/:id', scanController.getScan);
router.get('/reports/:id/:index?', scanController.getReport);

module.exports = router;
