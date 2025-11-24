
CREATE TABLE mobile_scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_name TEXT NOT NULL,
  package_name TEXT,
  version TEXT,
  platform TEXT NOT NULL,
  file_key TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  status TEXT NOT NULL,
  severity_critical INTEGER DEFAULT 0,
  severity_high INTEGER DEFAULT 0,
  severity_medium INTEGER DEFAULT 0,
  severity_low INTEGER DEFAULT 0,
  severity_info INTEGER DEFAULT 0,
  started_at DATETIME,
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE mobile_vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mobile_scan_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL,
  owasp_category TEXT NOT NULL,
  cvss_score REAL,
  cwe_id TEXT,
  recommendation TEXT,
  evidence TEXT,
  file_path TEXT,
  code_snippet TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mobile_scans_platform ON mobile_scans(platform);
CREATE INDEX idx_mobile_scans_status ON mobile_scans(status);
CREATE INDEX idx_mobile_vulnerabilities_scan_id ON mobile_vulnerabilities(mobile_scan_id);
CREATE INDEX idx_mobile_vulnerabilities_severity ON mobile_vulnerabilities(severity);
