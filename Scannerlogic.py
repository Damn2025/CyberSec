import json
import os

# 1. Load the Database
# In a real scanner, this might be a database call or loading a cached JSON file on startup.
def load_cwe_database(filepath="cwe_top_25_vulnerabilities.json"):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Database not found at {filepath}")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data

# 2. The Scanner Logic (Simulation)
class VulnerabilityScanner:
    def __init__(self, db_path):
        self.cwe_db = load_cwe_database(db_path)
        self.findings = []

    def get_cwe_details(self, cwe_id):
        """Helper to fetch full details by CWE ID"""
        for vuln in self.cwe_db['vulnerabilities']:
            if vuln['cwe_id'] == cwe_id:
                return vuln
        return None

    def scan_url(self, url):
        print(f"--- Scanning Web URL: {url} ---")
        
        # --- SIMULATED CHECK: CROSS-SITE SCRIPTING (XSS) ---
        # Logic: Your scanner detects a reflected parameter.
        # Instead of just saying "XSS Found", you map it to CWE-79.
        
        detected_cwe_id = "CWE-79" 
        vuln_details = self.get_cwe_details(detected_cwe_id)
        
        if vuln_details:
            finding = {
                "target": url,
                "type": "Web",
                "vulnerability_name": vuln_details['name'],
                "cwe_id": detected_cwe_id,
                "severity": vuln_details['severity'],
                "description": vuln_details['description'],
                "mitigation_advice": vuln_details['mitigation'],
                "technical_details": "Reflected payload found in 'q' parameter."
            }
            self.findings.append(finding)

    def scan_mobile_app(self, apk_path):
        print(f"--- Scanning Mobile APK: {apk_path} ---")

        # --- SIMULATED CHECK: HARDCODED CREDENTIALS ---
        # Logic: Your static analysis finds "api_key = '12345'"
        
        detected_cwe_id = "CWE-798"
        vuln_details = self.get_cwe_details(detected_cwe_id)

        if vuln_details:
            finding = {
                "target": apk_path,
                "type": "Mobile",
                "vulnerability_name": vuln_details['name'],
                "cwe_id": detected_cwe_id,
                "severity": vuln_details['severity'],
                "description": vuln_details['description'],
                "mitigation_advice": vuln_details['mitigation'],
                "technical_details": "Found 'AWS_SECRET' string in classes.dex"
            }
            self.findings.append(finding)

    def generate_report(self):
        print("\n=== FINAL SCAN REPORT ===")
        print(json.dumps(self.findings, indent=2))

# 3. Execution
if __name__ == "__main__":
    # Initialize Scanner
    scanner = VulnerabilityScanner("cwe_top_25_vulnerabilities.json")
    
    # Run Scans
    scanner.scan_url("http://example.com?q=<script>")
    scanner.scan_mobile_app("vulnerable_app.apk")
    
    # Generate Output
    scanner.generate_report()