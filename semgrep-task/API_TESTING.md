# API Testing Checkpoints

This document provides comprehensive testing checkpoints for all API endpoints. Use these to verify each API is working correctly.

## Prerequisites

1. **Backend is running**: `cd backend && npm start` (port 5000)
2. **Python engine exists**: Verify `auto-review.py` is in the root directory
3. **Python dependencies installed**: Semgrep, pandas, etc.

---

## Checkpoint 1: Health Check

**Endpoint**: `GET /health`

**Purpose**: Verify server is running

**Test Tool**: Browser or Postman

**Steps**:
1. Open browser to `http://localhost:5000/health`
2. You should see:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-14T...",
  "uptime": 123.456
}
```

**Pass Criteria**: ✅ Status 200, JSON response with healthy status

---

## Checkpoint 2: GitHub URL Scan

**Endpoint**: `POST /api/scan`

**Purpose**: Test GitHub repository scanning

**Test Tool**: Postman or curl

**Request**:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "type": "github",
    "url": "https://github.com/username/repository"
  }'
```

**Expected Response** (Success):
```json
{
  "success": true,
  "scanId": "scan_1737123456_abc123",
  "message": "Scan completed successfully",
  "reportPath": "Python_Review.xlsx",
  "duration": 45678
}
```

**Expected Response** (Error - Invalid URL):
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

**Test Cases**:
- ✅ Valid GitHub URL → Status 200, scan completes
- ✅ Invalid URL format → Status 400, validation error
- ✅ Missing URL → Status 400, validation error
- ✅ Private repo (if no auth) → Status 500, GitHub error

**Pass Criteria**: 
- ✅ Valid URL returns scanId and reportPath
- ✅ Invalid URL returns 400 with clear error message
- ✅ Scan appears in logs

---

## Checkpoint 3: File Upload Scan

**Endpoint**: `POST /api/scan`

**Purpose**: Test ZIP file upload scanning

**Test Tool**: Postman

**Steps**:
1. Create a ZIP file with some code files
2. In Postman:
   - Method: POST
   - URL: `http://localhost:5000/api/scan`
   - Body: form-data
   - Key: `file` (type: File)
   - Value: Select your ZIP file
   - Add key: `type`, value: `upload`

**Expected Response** (Success):
```json
{
  "success": true,
  "scanId": "scan_1737123456_xyz789",
  "message": "Scan completed successfully",
  "reportPath": "Python_Review.xlsx",
  "duration": 12345
}
```

**Test Cases**:
- ✅ Valid ZIP file → Status 200, scan completes
- ✅ File > 50MB → Status 400, size error
- ✅ Non-ZIP file → Status 400, type error
- ✅ No file uploaded → Status 400, validation error

**Pass Criteria**:
- ✅ ZIP file is accepted and processed
- ✅ Large files are rejected with clear error
- ✅ Extracted directory is cleaned up after scan

---

## Checkpoint 4: Get All Scans

**Endpoint**: `GET /api/scans`

**Purpose**: Retrieve scan history

**Test Tool**: Browser or curl

**Request**:
```bash
curl http://localhost:5000/api/scans
```

**Expected Response**:
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
      "updatedAt": "2026-01-14T10:15:45.000Z",
      "reportPath": "Python_Review.xlsx",
      "duration": 45000
    },
    {
      "id": "scan_1737123400_abc123",
      "type": "github",
      "input": "https://github.com/user/repo",
      "status": "failed",
      "createdAt": "2026-01-14T10:10:00.000Z",
      "updatedAt": "2026-01-14T10:10:10.000Z",
      "error": "GitHub repository not found"
    }
  ]
}
```

**Test Cases**:
- ✅ No scans yet → Returns empty array
- ✅ Multiple scans → Returns sorted by newest first
- ✅ Shows all scan statuses (pending, completed, failed)

**Pass Criteria**:
- ✅ Returns all scans
- ✅ Scans are ordered newest first
- ✅ Each scan has all required fields

---

## Checkpoint 5: Get Specific Scan

**Endpoint**: `GET /api/scans/:id`

**Purpose**: Retrieve details of a specific scan

**Request**:
```bash
curl http://localhost:5000/api/scans/scan_1737123456_xyz789
```

**Expected Response** (Found):
```json
{
  "success": true,
  "scan": {
    "id": "scan_1737123456_xyz789",
    "type": "upload",
    "input": "test-code.zip",
    "status": "completed",
    "createdAt": "2026-01-14T10:15:00.000Z",
    "updatedAt": "2026-01-14T10:15:45.000Z",
    "reportPath": "Python_Review.xlsx",
    "duration": 45000
  }
}
```

**Expected Response** (Not Found):
```json
{
  "success": false,
  "error": {
    "message": "Scan not found: invalid_id",
    "code": "SCAN_NOT_FOUND",
    "requestId": "req_...",
    "timestamp": "2026-01-14T..."
  }
}
```

**Test Cases**:
- ✅ Valid scan ID → Status 200, returns scan details
- ✅ Invalid scan ID → Status 404, not found error

**Pass Criteria**:
- ✅ Valid ID returns complete scan object
- ✅ Invalid ID returns 404

---

## Checkpoint 6: Download Report

**Endpoint**: `GET /api/reports/:id`

**Purpose**: Download Excel report for a completed scan

**Test Tool**: Browser or curl

**Request** (Browser):
```
http://localhost:5000/api/reports/scan_1737123456_xyz789
```

**Request** (curl):
```bash
curl -O -J http://localhost:5000/api/reports/scan_1737123456_xyz789
```

**Expected Behavior**:
- File download starts
- File name: `Python_Review.xlsx`
- File can be opened in Excel

**Test Cases**:
- ✅ Valid completed scan → Downloads Excel file
- ✅ Scan not found → Status 404
- ✅ Scan pending/failed → Status 400, report not available
- ✅ Report file missing → Status 404, file not found

**Pass Criteria**:
- ✅ Excel file downloads successfully
- ✅ File opens in Excel without errors
- ✅ Report contains scan results

---

## Checkpoint 7: Error Handling

**Purpose**: Verify consistent error responses

**Test Cases**:

### Invalid JSON
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d 'invalid json'
```
**Expected**: Status 400, JSON parse error

### Missing Python Engine
1. Temporarily rename `auto-review.py`
2. Try to create a scan
**Expected**: Status 500, Python engine not found

### Timeout Test
1. Create a very large repository scan
2. Wait for timeout (5 minutes)
**Expected**: Status 408, timeout error

**Pass Criteria**:
- ✅ All errors return JSON format
- ✅ Error messages are clear and actionable
- ✅ Errors include requestId for tracing

---

## Checkpoint 8: Logging

**Purpose**: Verify structured logging

**Steps**:
1. Check console output during API calls
2. Check `backend/logs/` directory
3. Open log file for today (e.g., `2026-01-14.log`)

**Expected Log Entry**:
```json
{"timestamp":"2026-01-14T10:15:00.000Z","requestId":"req_123","method":"POST","path":"/api/scan","ip":"::1","userAgent":"curl/7.68.0"}
```

**Pass Criteria**:
- ✅ Each request is logged
- ✅ Log files are created daily
- ✅ Logs include timestamp, requestId, method, path

---

## Checkpoint 9: Cleanup

**Purpose**: Verify temp files are cleaned up

**Steps**:
1. Upload a ZIP file scan
2. Check `backend/uploads/` directory during scan
3. Wait for scan to complete
4. Check `backend/uploads/` again

**Pass Criteria**:
- ✅ Uploaded ZIP file is deleted after scan
- ✅ Extracted directory is deleted after scan
- ✅ Only recent uploads remain if scan fails

---

## Checkpoint 10: Concurrent Scans

**Purpose**: Test system behavior with multiple scans

**Steps**:
1. Start scan #1 (GitHub URL)
2. Immediately start scan #2 (different URL)
3. Both should complete independently

**Expected Behavior**:
- Each scan gets unique ID
- Both scans execute sequentially (Python engine limitation)
- Both complete successfully

**Pass Criteria**:
- ✅ Multiple scans don't interfere
- ✅ Each scan tracked independently
- ✅ Both reports generated correctly

---

## Quick Test Script

Save as `test-apis.sh`:

```bash
#!/bin/bash

echo "=== API Testing Script ==="
echo ""

echo "1. Health Check"
curl -s http://localhost:5000/health | json_pp
echo ""

echo "2. Get Scans (should be empty initially)"
curl -s http://localhost:5000/api/scans | json_pp
echo ""

echo "3. Create GitHub Scan (use a real repo)"
curl -s -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"type":"github","url":"https://github.com/your-username/your-repo"}' | json_pp
echo ""

echo "4. Get Scans Again (should show the scan)"
curl -s http://localhost:5000/api/scans | json_pp
echo ""

echo "Done! Check the output above for any errors."
```

Run: `chmod +x test-apis.sh && ./test-apis.sh`

---

## Summary Checklist

- [ ] Health check returns 200
- [ ] GitHub URL scans work
- [ ] File uploads work
- [ ] Invalid inputs rejected with 400
- [ ] Scan history endpoint works
- [ ] Individual scan retrieval works
- [ ] Report download works
- [ ] Errors return consistent JSON format
- [ ] Logs are created and structured
- [ ] Temp files are cleaned up
- [ ] Multiple scans work independently

---

## Troubleshooting

**Backend won't start**:
- Check `backend/package.json` dependencies installed: `npm install`
- Verify port 5000 is not in use: `netstat -ano | findstr :5000`

**Python execution fails**:
- Verify `auto-review.py` exists in root directory
- Check Python is in PATH: `python --version`
- Verify Python dependencies: `pip list | grep semgrep`

**File upload fails**:
- Check `backend/uploads/` directory exists and is writable
- Verify file size < 50MB

**Report download fails**:
- Check report file exists at root directory
- Verify file permissions

---

**End of Testing Checkpoints**

Use these checkpoints systematically to verify everything works!
