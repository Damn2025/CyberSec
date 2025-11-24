# CyberSec

This is a full-stack **Cyber Security Scanning Application** designed to perform security scans on both **Websites** and **Mobile Applications** (Android/iOS). It uses a modern architecture with **React** on the frontend and **Cloudflare Workers** on the backend.

## 🏗️ Architecture Overview

### Backend: Cloudflare Workers (`src/worker/`)
The core logic runs on Cloudflare's global network.
*   **`index.ts`**: The API entry point using **Hono** to handle HTTP requests.
*   **`scanner.ts`**: Logic for scanning websites for common vulnerabilities.
*   **`mobile-scanner.ts`**: Logic for scanning mobile application files.
*   **`report-generator.ts`**: Generates PDF reports for scan results.

### Frontend: React App (`src/react-app/`)
A modern dashboard for managing scans and viewing results.
*   **Tech Stack**: React 19, Tailwind CSS, Recharts, Lucide React.
*   **Pages**: Dashboard, Web Scan Details, Mobile Scan Details.

### Database & Storage
*   **Cloudflare D1 (SQL)**: Stores scan results and vulnerability data.
    *   `scans` / `vulnerabilities`: For web scans.
    *   `mobile_scans` / `mobile_vulnerabilities`: For mobile app scans.
*   **Cloudflare R2**: Stores uploaded mobile application files for scanning.

### Shared Code (`src/shared/`)
*   **`types.ts`**: TypeScript definitions and Zod schemas shared between frontend and backend to ensure type safety.

## 📂 Project Structure

```text
/src
  /react-app      # Frontend React application
    /components   # Reusable UI components
    /pages        # Application views (Dashboard, Details)
  /worker         # Cloudflare Worker (Backend API)
  /shared         # Shared types and validation schemas
/migrations       # Database schema migrations (D1)
```

## 🗄️ Database Schema

The application uses Cloudflare D1 (SQLite) with the following structure:

### Web Scans

**`scans`**
Stores the high-level details of each web security scan.
- `id`: Unique identifier
- `target_url`: The URL being scanned
- `scan_type`: Type of scan (e.g., quick, full)
- `status`: Current state (pending, running, completed, failed)
- `severity_*`: Counts for critical, high, medium, low, and info issues
- `timestamps`: started_at, completed_at, created_at

**`vulnerabilities`**
Stores individual security findings linked to a scan.
- `scan_id`: Foreign key to `scans`
- `title`, `description`: Details of the finding
- `severity`: Critical, High, Medium, Low, or Info
- `category`: Vulnerability category (e.g., XSS, SQLi)
- `cvss_score`: Standardized severity score
- `evidence`: Proof of the vulnerability
- `recommendation`: How to fix the issue

### Mobile Scans

**`mobile_scans`**
Stores details of uploaded mobile applications.
- `id`: Unique identifier
- `app_name`, `package_name`, `version`: App metadata
- `platform`: 'android' or 'ios'
- `file_key`: Reference to the file in R2 storage
- `status`: Scan execution status
- `severity_*`: Vulnerability counts

**`mobile_vulnerabilities`**
Stores security findings for mobile apps.
- `mobile_scan_id`: Foreign key to `mobile_scans`
- `owasp_category`: Mapping to OWASP Mobile Top 10
- `file_path`: Specific file in the app package where the issue was found
- `code_snippet`: Relevant code context (if available)
- `severity`, `title`, `description`, `recommendation`: Standard finding details

## 🚀 Key Features

1.  **Web Scanning**: Enter a URL to asynchronously scan for web vulnerabilities.
2.  **Mobile Scanning**: Upload mobile app binaries (APK/IPA) to scan for security issues.
3.  **Reporting**: Generate detailed PDF reports of scan findings.
4.  **Dashboard**: Visual analytics of security posture and severity counts (Critical, High, Medium, Low).

## 📡 API Documentation

All API endpoints are prefixed with `/api`. The API uses JSON for request/response bodies unless otherwise specified.

### Web Scan Endpoints

#### `GET /api/scans`
Retrieve all web scans.

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "target_url": "https://example.com",
    "scan_type": "quick",
    "status": "completed",
    "severity_critical": 2,
    "severity_high": 5,
    "severity_medium": 10,
    "severity_low": 3,
    "severity_info": 1,
    "started_at": "2024-01-01T00:00:00Z",
    "completed_at": "2024-01-01T00:05:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:05:00Z"
  }
]
```
- Returns up to 50 most recent scans, ordered by creation date (newest first)
- **Error Responses:**
  - `500`: Database error

---

#### `GET /api/scans/:id`
Retrieve a specific web scan by ID.

**Parameters:**
- `id` (path): Scan ID

**Response:** `200 OK`
```json
{
  "id": 1,
  "target_url": "https://example.com",
  "scan_type": "quick",
  "status": "completed",
  "severity_critical": 2,
  "severity_high": 5,
  "severity_medium": 10,
  "severity_low": 3,
  "severity_info": 1,
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": "2024-01-01T00:05:00Z",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:05:00Z"
}
```
- **Error Responses:**
  - `404`: Scan not found

---

#### `GET /api/scans/:id/vulnerabilities`
Get all vulnerabilities for a specific scan.

**Parameters:**
- `id` (path): Scan ID

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "scan_id": 1,
    "title": "SQL Injection Vulnerability",
    "description": "The application is vulnerable to SQL injection attacks...",
    "severity": "critical",
    "category": "SQLi",
    "cvss_score": 9.8,
    "cwe_id": "CWE-89",
    "recommendation": "Use parameterized queries...",
    "evidence": "Found in /api/users?id=1' OR '1'='1",
    "created_at": "2024-01-01T00:05:00Z",
    "updated_at": "2024-01-01T00:05:00Z"
  }
]
```
- Returns vulnerabilities ordered by creation date (newest first)
- **Error Responses:**
  - `500`: Database error

---

#### `POST /api/scans`
Create a new web security scan.

**Request Body:**
```json
{
  "target_url": "https://example.com",
  "scan_type": "quick"
}
```

**Fields:**
- `target_url` (string, required): Valid URL to scan
- `scan_type` (string, required): One of `"quick"`, `"standard"`, `"comprehensive"`, `"api"`, or `"mobile"`

**Response:** `200 OK`
```json
{
  "id": 1,
  "target_url": "https://example.com",
  "scan_type": "quick",
  "status": "running",
  "severity_critical": 0,
  "severity_high": 0,
  "severity_medium": 0,
  "severity_low": 0,
  "severity_info": 0,
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": null,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```
- Scan runs asynchronously. Status will be updated to `"completed"` or `"failed"` when finished.
- **Error Responses:**
  - `400`: Invalid request body or validation error
  - `500`: Failed to create scan

---

#### `DELETE /api/scans/:id`
Delete a web scan and all associated vulnerabilities.

**Parameters:**
- `id` (path): Scan ID

**Response:** `200 OK`
```json
{
  "success": true
}
```
- Automatically deletes all related vulnerabilities (CASCADE delete)
- **Error Responses:**
  - `500`: Database error

---

#### `GET /api/scans/:id/export`
Export scan report in various formats.

**Parameters:**
- `id` (path): Scan ID
- `format` (query, optional): Export format - `"pdf"` (default), `"json"`, `"csv"`, or `"html"`

**Response:** `200 OK`
- Returns file download with appropriate `Content-Type` header
- **File naming:** `cybersec-report-{id}.{ext}`

**Example:**
```
GET /api/scans/1/export?format=pdf
GET /api/scans/1/export?format=json
GET /api/scans/1/export?format=csv
GET /api/scans/1/export?format=html
```

- **Error Responses:**
  - `404`: Scan not found
  - `400`: Invalid format
  - `500`: Failed to generate report

---

### Mobile Scan Endpoints

#### `GET /api/mobile-scans`
Retrieve all mobile scans.

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "app_name": "MyApp.apk",
    "package_name": "com.example.myapp",
    "version": "1.0.0",
    "platform": "android",
    "file_key": "mobile-apps/1234567890-MyApp.apk",
    "file_size": 5242880,
    "status": "completed",
    "severity_critical": 1,
    "severity_high": 3,
    "severity_medium": 7,
    "severity_low": 2,
    "severity_info": 0,
    "started_at": "2024-01-01T00:00:00Z",
    "completed_at": "2024-01-01T00:10:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:10:00Z"
  }
]
```
- Returns up to 50 most recent scans, ordered by creation date (newest first)
- **Error Responses:**
  - `500`: Database error

---

#### `GET /api/mobile-scans/:id`
Retrieve a specific mobile scan by ID.

**Parameters:**
- `id` (path): Mobile scan ID

**Response:** `200 OK`
```json
{
  "id": 1,
  "app_name": "MyApp.apk",
  "package_name": "com.example.myapp",
  "version": "1.0.0",
  "platform": "android",
  "file_key": "mobile-apps/1234567890-MyApp.apk",
  "file_size": 5242880,
  "status": "completed",
  "severity_critical": 1,
  "severity_high": 3,
  "severity_medium": 7,
  "severity_low": 2,
  "severity_info": 0,
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": "2024-01-01T00:10:00Z",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:10:00Z"
}
```
- **Error Responses:**
  - `404`: Mobile scan not found

---

#### `GET /api/mobile-scans/:id/vulnerabilities`
Get all vulnerabilities for a specific mobile scan.

**Parameters:**
- `id` (path): Mobile scan ID

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "mobile_scan_id": 1,
    "title": "Insecure Data Storage",
    "description": "The app stores sensitive data in plaintext...",
    "severity": "high",
    "owasp_category": "M2",
    "cvss_score": 7.5,
    "cwe_id": "CWE-312",
    "recommendation": "Encrypt sensitive data before storage...",
    "evidence": "Found in SharedPreferences",
    "file_path": "res/xml/preferences.xml",
    "code_snippet": "SharedPreferences.Editor.putString(\"password\", password);",
    "created_at": "2024-01-01T00:10:00Z",
    "updated_at": "2024-01-01T00:10:00Z"
  }
]
```
- Returns vulnerabilities ordered by creation date (newest first)
- **Error Responses:**
  - `500`: Database error

---

#### `POST /api/mobile-scans`
Create a new mobile security scan with file upload.

**Request:** `multipart/form-data`

**Form Fields:**
- `file` (File, required): Mobile app file
  - Android: `.apk` file
  - iOS: `.ipa` or `.zip` file
- `platform` (string, required): `"android"` or `"ios"`

**Response:** `200 OK`
```json
{
  "id": 1,
  "app_name": "MyApp.apk",
  "package_name": null,
  "version": null,
  "platform": "android",
  "file_key": "mobile-apps/1234567890-MyApp.apk",
  "file_size": 5242880,
  "status": "running",
  "severity_critical": 0,
  "severity_high": 0,
  "severity_medium": 0,
  "severity_low": 0,
  "severity_info": 0,
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": null,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```
- File is stored in R2 bucket
- Scan runs asynchronously. Status will be updated to `"completed"` or `"failed"` when finished.
- App metadata (package_name, version) is extracted during scan
- **Error Responses:**
  - `400`: No file provided, invalid platform, or invalid file type
  - `500`: R2 bucket not configured or failed to create scan

---

#### `DELETE /api/mobile-scans/:id`
Delete a mobile scan, associated vulnerabilities, and the uploaded file from R2 storage.

**Parameters:**
- `id` (path): Mobile scan ID

**Response:** `200 OK`
```json
{
  "success": true
}
```
- Automatically deletes the file from R2 storage and all related vulnerabilities
- **Error Responses:**
  - `500`: Database error

---

#### `GET /api/mobile-scans/:id/export`
Export mobile scan report in various formats.

**Parameters:**
- `id` (path): Mobile scan ID
- `format` (query, optional): Export format - `"pdf"` (default), `"json"`, `"csv"`, or `"html"`

**Response:** `200 OK`
- Returns file download with appropriate `Content-Type` header
- **File naming:** `mobile-security-report-{id}.{ext}`

**Example:**
```
GET /api/mobile-scans/1/export?format=pdf
GET /api/mobile-scans/1/export?format=json
GET /api/mobile-scans/1/export?format=csv
GET /api/mobile-scans/1/export?format=html
```

- **Error Responses:**
  - `404`: Mobile scan not found
  - `400`: Invalid format
  - `500`: Failed to generate report

---

### Dashboard Endpoints

#### `GET /api/dashboard/stats`
Get dashboard statistics and summary metrics.

**Response:** `200 OK`
```json
{
  "totalScans": 150,
  "completedScans": 145,
  "runningScans": 3,
  "totalVulnerabilities": 1250,
  "criticalVulnerabilities": 25
}
```

**Fields:**
- `totalScans`: Total number of web scans
- `completedScans`: Number of completed scans
- `runningScans`: Number of scans currently running
- `totalVulnerabilities`: Total number of vulnerabilities found across all scans
- `criticalVulnerabilities`: Number of critical severity vulnerabilities

---

### Error Response Format

All error responses follow this format:

```json
{
  "error": "Error message description"
}
```

**Common HTTP Status Codes:**
- `200`: Success
- `400`: Bad Request (validation error, invalid parameters)
- `404`: Not Found (resource doesn't exist)
- `500`: Internal Server Error (database error, server error)

## 🛠️ Getting Started

This app was created using [GetMocha](https://getmocha.com).

### Prerequisites
*   Node.js installed
*   npm installed

### Running the Development Server

To start the local development server:

```bash
npm install
npm run dev
```

### Other Commands

*   `npm run build`: Build both the React app and the Worker for production.
*   `npm run cf-typegen`: Generate TypeScript types for Cloudflare bindings.
*   `npm run check`: Run typechecks and build verification.

## 🤝 Community

Need help or want to join the community? Join our [Discord](https://discord.gg/shDEGBSe2d).
