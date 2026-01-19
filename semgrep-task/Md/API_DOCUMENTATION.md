# API Documentation - Code Review System

> **Base URL**: `http://localhost:5000`  
> **Version**: 1.0.0  
> **Last Updated**: January 16, 2026

---

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Health Check](#health-check)
- [Scan APIs](#scan-apis)
- [Rule Generation APIs](#rule-generation-apis)
- [Error Handling](#error-handling)
- [File Structure](#file-structure)

---

## Overview

This API provides endpoints for automated code review using Semgrep. It supports scanning code from GitHub repositories or uploaded ZIP files and generating custom Semgrep rules.

**Tech Stack**:
- Node.js + Express
- Python (Semgrep)
- Multer (file uploads)
- CORS enabled

---

## Authentication

Currently, the API does not require authentication. All endpoints are publicly accessible.

> [!WARNING]
> For production deployment, implement proper authentication and authorization mechanisms.

---

## Health Check

### Check Server Status

**Endpoint**: `GET /health`

**Description**: Verify if the backend server is running and responsive.

**Location**: [`backend/server.js:33-39`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/server.js#L33-L39)

**Request**:
```http
GET /health
```

**Response** (200 OK):
```json
{
  "status": "healthy",
  "timestamp": "2026-01-16T05:40:00.000Z",
  "uptime": 1234.567
}
```

---

## Scan APIs

### 1. Create a New Scan

**Endpoint**: `POST /api/scan`

**Description**: Initiate a code scan from a GitHub repository URL or uploaded ZIP file.

**Route Definition**: [`backend/routes/scan.routes.js:28`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/routes/scan.routes.js#L28)  
**Controller**: [`backend/controllers/scan.controller.js:12-114`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/controllers/scan.controller.js#L12-L114)

#### Option A: GitHub URL Scan

**Request**:
```http
POST /api/scan
Content-Type: application/json

{
  "type": "github",
  "url": "https://github.com/owner/repo.git"
}
```

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be "github" |
| `url` | string | Yes | Valid GitHub repository URL |

#### Option B: File Upload Scan

**Request**:
```http
POST /api/scan
Content-Type: multipart/form-data

file: <ZIP_FILE>
type: upload
```

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be "upload" |
| `file` | File | Yes | ZIP file containing code (max 50MB) |

**Success Response** (200 OK):
```json
{
  "success": true,
  "scanId": "scan_1737012345678",
  "message": "Scan completed successfully",
  "reportPaths": [
    "reports/report_1737012345678.html",
    "reports/report_1737012345678.json"
  ],
  "reportCount": 2,
  "duration": 5.67
}
```

**Error Responses**:

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | `INVALID_GITHUB_URL` | Invalid GitHub URL format |
| 400 | `INVALID_FILE_UPLOAD` | Invalid or missing file |
| 400 | `INVALID_SCAN_TYPE` | Type must be 'github' or 'upload' |
| 500 | `SCAN_FAILED` | Scan execution failed |

**Example Error**:
```json
{
  "error": {
    "code": "INVALID_GITHUB_URL",
    "message": "Invalid GitHub URL format",
    "status": 400
  }
}
```

---

### 2. Get All Scans

**Endpoint**: `GET /api/scans`

**Description**: Retrieve a list of all scans with their current status.

**Route Definition**: [`backend/routes/scan.routes.js:29`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/routes/scan.routes.js#L29)  
**Controller**: [`backend/controllers/scan.controller.js:120-132`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/controllers/scan.controller.js#L120-L132)

**Request**:
```http
GET /api/scans
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "count": 3,
  "scans": [
    {
      "id": "scan_1737012345678",
      "type": "github",
      "input": "https://github.com/owner/repo.git",
      "status": "completed",
      "reportPaths": ["reports/report_1737012345678.html"],
      "createdAt": "2026-01-16T05:30:00.000Z",
      "completedAt": "2026-01-16T05:30:05.000Z",
      "duration": 5.67
    },
    {
      "id": "scan_1737012345679",
      "type": "upload",
      "input": "project.zip",
      "status": "failed",
      "error": "Git repository not found",
      "createdAt": "2026-01-16T05:35:00.000Z"
    }
  ]
}
```

**Scan Status Values**:
- `pending`: Scan is queued
- `running`: Scan is in progress
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error

---

### 3. Get Specific Scan Details

**Endpoint**: `GET /api/scans/:id`

**Description**: Retrieve detailed information about a specific scan.

**Route Definition**: [`backend/routes/scan.routes.js:30`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/routes/scan.routes.js#L30)  
**Controller**: [`backend/controllers/scan.controller.js:138-157`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/controllers/scan.controller.js#L138-L157)

**URL Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Unique scan identifier |

**Request**:
```http
GET /api/scans/scan_1737012345678
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "scan": {
    "id": "scan_1737012345678",
    "type": "github",
    "input": "https://github.com/owner/repo.git",
    "status": "completed",
    "reportPaths": [
      "reports/report_1737012345678.html",
      "reports/report_1737012345678.json"
    ],
    "createdAt": "2026-01-16T05:30:00.000Z",
    "completedAt": "2026-01-16T05:30:05.000Z",
    "duration": 5.67
  }
}
```

**Error Response** (404 Not Found):
```json
{
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "Scan not found: scan_invalid",
    "status": 404
  }
}
```

---

### 4. Download Scan Report

**Endpoint**: `GET /api/reports/:id/:index?`

**Description**: Download the generated report file for a completed scan.

**Route Definition**: [`backend/routes/scan.routes.js:31`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/routes/scan.routes.js#L31)  
**Controller**: [`backend/controllers/scan.controller.js:164-228`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/controllers/scan.controller.js#L164-L228)

**URL Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Scan identifier |
| `index` | number | No | Report index (default: 0) |

**Request Examples**:
```http
# Download first report (default)
GET /api/reports/scan_1737012345678

# Download specific report by index
GET /api/reports/scan_1737012345678/0
GET /api/reports/scan_1737012345678/1
```

**Success Response**: 
- File download with appropriate headers
- Content-Disposition header with filename

**Error Responses**:

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 404 | `SCAN_NOT_FOUND` | Scan does not exist |
| 400 | `REPORT_NOT_AVAILABLE` | Scan not completed or no reports |
| 400 | `INVALID_REPORT_INDEX` | Invalid index number |
| 404 | `REPORT_FILE_NOT_FOUND` | Report file missing from disk |
| 500 | `DOWNLOAD_FAILED` | Server error during download |

---

## Rule Generation APIs

### Generate Custom Semgrep Rule

**Endpoint**: `POST /api/rules/generate`

**Description**: Generate a custom Semgrep rule using AI based on a natural language description.

**Route Definition**: [`backend/routes/rule.routes.js:6`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/routes/rule.routes.js#L6)  
**Controller**: [`backend/controllers/rule.controller.js:3-66`](file:///e:/SY%20CSE/MINI%20PROJECT/CodeReview-1/optimized-final-code/semgrep-task/backend/controllers/rule.controller.js#L3-L66)

**Request**:
```http
POST /api/rules/generate
Content-Type: application/json

{
  "description": "Detect hardcoded passwords in variable assignments",
  "language": "python",
  "severity": "ERROR",
  "category": "security"
}
```

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | Natural language rule description |
| `language` | string | Yes | Target language (python, javascript, java, go) |
| `severity` | string | No | ERROR, WARNING, or INFO (default: WARNING) |
| `category` | string | No | Rule category (default: security) |

**Supported Languages**:
- `python`
- `javascript`
- `java`
- `go`

**Severity Levels**:
- `ERROR`: Critical issues
- `WARNING`: Important issues (default)
- `INFO`: Informational findings

**Success Response** (200 OK):
```json
{
  "success": true,
  "message": "Rule generated successfully",
  "filePath": "rules/python-rules.yml",
  "yaml": "rules:\n  - id: detect-hardcoded-passwords\n    patterns:\n      - pattern: password = \"...\"\n    message: Hardcoded password detected\n    languages: [python]\n    severity: ERROR\n",
  "duration": 2.34
}
```

**Error Responses**:

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | `INVALID_REQUEST` | Missing or invalid parameters |

**Example Errors**:
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Rule description is required"
  }
}
```

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Language must be one of: python, javascript, java, go"
  }
}
```

---

## Error Handling

All API errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "status": 400
  }
}
```

**Common Error Codes**:

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_GITHUB_URL` | 400 | GitHub URL is malformed or invalid |
| `INVALID_FILE_UPLOAD` | 400 | Uploaded file is invalid or too large |
| `INVALID_SCAN_TYPE` | 400 | Scan type must be 'github' or 'upload' |
| `SCAN_NOT_FOUND` | 404 | Scan ID does not exist |
| `REPORT_NOT_AVAILABLE` | 400 | Report not ready or doesn't exist |
| `INVALID_REPORT_INDEX` | 400 | Report index out of bounds |
| `REPORT_FILE_NOT_FOUND` | 404 | Report file missing from filesystem |
| `SCAN_FAILED` | 500 | Scan execution encountered an error |
| `DOWNLOAD_FAILED` | 500 | File download failed |
| `INVALID_REQUEST` | 400 | Request validation failed |

---

## File Structure

```
backend/
├── server.js                    # Main server entry point
├── routes/
│   ├── scan.routes.js          # Scan-related endpoints
│   └── rule.routes.js          # Rule generation endpoints
├── controllers/
│   ├── scan.controller.js      # Scan business logic
│   └── rule.controller.js      # Rule generation logic
├── services/
│   ├── pythonExecutor.js       # Python/Semgrep execution
│   ├── scanManager.js          # In-memory scan state management
│   └── ruleGenerator.js        # AI-based rule generation
├── middleware/
│   ├── logger.js               # Request/response logging
│   ├── errorHandler.js         # Global error handling
│   └── validation.js           # Input validation helpers
└── utils/
    └── fileHandler.js          # File system operations
```

---

## Quick Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/health` | Server health check |
| POST | `/api/scan` | Create new code scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/:id` | Get scan details |
| GET | `/api/reports/:id/:index?` | Download scan report |
| POST | `/api/rules/generate` | Generate custom Semgrep rule |

---

## Notes

> [!IMPORTANT]
> - Maximum file upload size: **50MB**
> - Supported archive format: **ZIP only**
> - GitHub URLs must end with `.git`
> - Private repositories require authentication (not yet implemented)

> [!TIP]
> Use the health check endpoint (`/health`) to verify the server is running before making other API calls.

---

## Contact & Support

For issues or questions, please refer to the project repository or contact the development team.

**Project Location**: `e:\SY CSE\MINI PROJECT\CodeReview-1\optimized-final-code\semgrep-task`
