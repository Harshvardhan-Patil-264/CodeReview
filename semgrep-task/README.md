# Code Review Platform

**Internal Company Tool** for static code analysis of Python, Java, JavaScript, and Go codebases.

This platform provides a web interface for the existing Python-based code review engine, enabling scans of GitHub repositories and uploaded ZIP files with Excel report generation.

---

## 📋 Overview

The Code Review Platform consists of three main components:

1. **Python Engine** (`auto-review.py`) - Production-tested static analysis engine using Semgrep
2. **Backend API** (Node.js/Express) - Secure execution layer and REST API
3. **Frontend UI** (React/Vite) - Clean, internal-tool interface

```
┌─────────────┐
│   React UI  │ ← User interacts here
└──────┬──────┘
       │ HTTP/REST
┌──────▼──────┐
│ Node.js API │ ← Validates, executes, manages
└──────┬──────┘
       │ spawn()
┌──────▼──────┐
│ Python CLI  │ ← Scans code, generates reports
└─────────────┘
```

---

## 🏗️ Architecture

### Backend (Node.js/Express)

- **Server**: Express with CORS, JSON parsing, structured logging
- **Routes**: `/api/scan`, `/api/scans`, `/api/scans/:id`, `/api/reports/:id`
- **Controllers**: Request validation, scan orchestration, report serving
- **Services**:
  - `pythonExecutor.js` - Secure Python execution via `spawn()` with timeout
  - `scanManager.js` - In-memory scan tracking and metadata
  - `fileHandler.js` - ZIP extraction and cleanup
- **Middleware**:
  - `logger.js` - Structured request/response logging
  - `errorHandler.js` - Consistent error responses
  - `validation.js` - Input sanitization and validation

### Frontend (React/Vite)

- **Components**:
  - `ScanForm` - GitHub URL or ZIP upload input
  - `ProgressIndicator` - Real-time scan progress
  - `ScanHistory` - List of completed scans with download
- **Services**:
  - `apiService.js` - Axios-based API client
- **Styling**: Clean, internal-tool CSS (no frameworks)

### Python Engine (Existing)

- **Entry Point**: `auto-review.py` (CLI)
- **Features**:
  - Scans local directories and GitHub repos
  - Supports Python, Java, JavaScript, Go
  - Validates code headers and version control tables
  - Generates Excel reports (`.xlsx`)

---

## 🔒 Security Considerations

### Command Injection Prevention

- ✅ Uses `child_process.spawn()` with array arguments (NOT `exec()`)
- ✅ All user inputs sanitized and validated
- ✅ No shell interpolation

### File Upload Safety

- ✅ File size limited to 50MB
- ✅ Only ZIP files accepted (MIME type + extension verification)
- ✅ Files extracted to isolated temp directories
- ✅ Path traversal prevented via sanitization
- ✅ Automatic cleanup of temp files post-scan

### Python Execution Sandboxing

- ✅ Working directory restricted to project root
- ✅ 5-minute timeout enforced
- ✅ All stdout/stderr captured and logged
- ✅ Process failures handled gracefully

---

## 🚀 Setup Instructions

### Prerequisites

- **Node.js** v18+ (LTS recommended)
- **Python** 3.8+
- **Python Dependencies**:
  ```bash
  pip install semgrep pandas openpyxl python-dotenv requests pyyaml
  ```

### 1. Install Backend Dependencies

```bash
cd backend
npm install
```

### 2. Install Frontend Dependencies

```bash
cd frontend
npm install
```

### 3. Verify Python Engine

```bash
# Test the Python engine directly
python auto-review.py /path/to/test/code
```

You should see output like:
```
🚀 Initializing security engine... Please wait.
✨ Created new report: Python_Review.xlsx
✅ All documents scanned successfully.
```

### 4. Start Backend Server

```bash
cd backend
npm start
```

Server runs on `http://localhost:5000`

### 5. Start Frontend Dev Server

```bash
cd frontend
npm run dev
```

Frontend runs on `http://localhost:5173`

### 6. Access the Application

Open browser to `http://localhost:5173`

---

## 📖 API Documentation

### POST /api/scan

Create a new scan (GitHub URL or uploaded ZIP).

**Request (GitHub)**:
```json
{
  "type": "github",
  "url": "https://github.com/username/repository"
}
```

**Request (Upload)**: 
- Content-Type: `multipart/form-data`
- Field: `file` (ZIP file)
- Field: `type` (value: "upload")

**Response (Success)**:
```json
{
  "success": true,
  "scanId": "scan_1737123456_abc123",
  "message": "Scan completed successfully",
  "reportPath": "Python_Review.xlsx",
  "duration": 45678
}
```

**Response (Error)**:
```json
{
  "success": false,
  "error": {
    "message": "Invalid GitHub URL format...",
    "code": "INVALID_GITHUB_URL",
    "requestId": "req_...",
    "timestamp": "2026-01-14T..."
  }
}
```

---

### GET /api/scans

Get all scans (sorted newest first).

**Response**:
```json
{
  "success": true,
  "count": 2,
  "scans": [
    {
      "id": "scan_1737123456_xyz789",
      "type": "upload",
      "input": "test-code.zip",
      "status": "completed",
      "createdAt": "2026-01-14T10:15:00.000Z",
      "reportPath": "Python_Review.xlsx",
      "duration": 45000
    }
  ]
}
```

---

### GET /api/scans/:id

Get specific scan by ID.

**Response**:
```json
{
  "success": true,
  "scan": {
    "id": "scan_1737123456_xyz789",
    "type": "upload",
    "input": "test-code.zip",
    "status": "completed",
    "createdAt": "2026-01-14T10:15:00.000Z",
    "reportPath": "Python_Review.xlsx",
    "duration": 45000
  }
}
```

---

### GET /api/reports/:id

Download Excel report for a completed scan.

**Response**: Binary `.xlsx` file with appropriate headers.

---

## 🧪 Testing

Comprehensive testing guide available in [`API_TESTING.md`](./API_TESTING.md).

**Quick Smoke Test**:

1. Start backend: `cd backend && npm start`
2. Start frontend: `cd frontend && npm run dev`
3. Open `http://localhost:5173`
4. Enter a GitHub URL (or upload a ZIP)
5. Click "Start Scan"
6. Wait for completion
7. Click "Download Report"

---

## 📂 Project Structure

```
code-review-platform/
│
├── backend/
│   ├── controllers/        # Request handlers
│   ├── middleware/         # Validation, logging, errors
│   ├── routes/             # API endpoints
│   ├── services/           # Python executor, scan manager
│   ├── utils/              # File handler utilities
│   ├── logs/               # Daily log files
│   ├── uploads/            # Temporary upload storage
│   ├── reports/            # (Future: persistent reports)
│   ├── package.json
│   └── server.js           # Entry point
│
├── frontend/
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── services/       # API client
│   │   ├── App.jsx         # Main app
│   │   ├── main.jsx        # Entry point
│   │   └── index.css       # Styles
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── engine/                 # (Symbolic: Python engine files)
│   ├── auto-review.py
│   ├── github_handler.py
│   └── rules/
│
├── .gitignore
├── README.md               # This file
└── API_TESTING.md          # Testing guide
```

---

## 🚨 Known Limitations

1. **No Authentication**: This is an internal tool. Deploy only on trusted networks.
2. **No Database**: Scan history is in-memory. Restart clears history.
3. **Single Scan Execution**: Python engine runs one scan at a time (backend queues).
4. **No Multi-User Support**: Not designed for concurrent multi-user scenarios.
5. **GitHub Public Repos Only**: No support for private repos (requires auth).
6. **Report Storage**: Reports saved to root directory (no cleanup).

---

## 🛠️ Troubleshooting

### Backend won't start
- Check port 5000 is not in use: `netstat -ano | findstr :5000`
- Install dependencies: `cd backend && npm install`

### Python execution fails
- Verify `auto-review.py` exists in root
- Check Python in PATH: `python --version`
- Install Python deps: `pip install semgrep pandas openpyxl`

### File upload fails
- Verify `backend/uploads/` exists and is writable
- Check file size < 50MB
- Ensure file is a valid ZIP

### Report download fails
- Check scan status is "completed"
- Verify report file exists in root directory

---

## 📝 Logs

Logs are written to:
- **Console**: Real-time request/response logs
- **Files**: `backend/logs/YYYY-MM-DD.log` (structured JSON, one entry per line)

Example log entry:
```json
{
  "timestamp": "2026-01-14T10:15:00.000Z",
  "requestId": "req_1737123456_abc123",
  "method": "POST",
  "path": "/api/scan",
  "ip": "::1"
}
```

---

## 🔮 Future Enhancements

- [ ] Database persistence (PostgreSQL/MongoDB)
- [ ] Authentication (JWT tokens)
- [ ] User management
- [ ] Scan queue with priority
- [ ] Report history and cleanup
- [ ] WebSocket for real-time progress
- [ ] GitHub OAuth for private repos
- [ ] Docker containerization
- [ ] CI/CD pipeline

---

## 📄 License

Internal company tool. Not for public distribution.

---

## 👥 Contact

For questions or issues, contact the development team.

---

**End of README**
