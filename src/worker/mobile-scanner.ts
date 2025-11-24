import JSZip from 'jszip';
import { parseString } from 'xml2js';
import { parse as parsePlist } from 'plist';

interface MobileScannerConfig {
  platform: 'android' | 'ios';
  fileBuffer: ArrayBuffer;
  fileName: string;
}

interface MobileVulnerabilityResult {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp_category: string;
  cvss_score?: number;
  cwe_id?: string;
  recommendation: string;
  evidence?: string;
  file_path?: string;
  code_snippet?: string;
}

interface AppMetadata {
  appName: string;
  packageName: string;
  version: string;
}

export class MobileSecurityScanner {
  private platform: 'android' | 'ios';
  private fileBuffer: ArrayBuffer;
  private fileName: string;
  private vulnerabilities: MobileVulnerabilityResult[] = [];
  private appMetadata: AppMetadata = { appName: '', packageName: '', version: '' };
  private zip: JSZip | null = null;

  constructor(config: MobileScannerConfig) {
    this.platform = config.platform;
    this.fileBuffer = config.fileBuffer;
    this.fileName = config.fileName;
  }

  async scan(): Promise<{ vulnerabilities: MobileVulnerabilityResult[]; metadata: AppMetadata }> {
    this.vulnerabilities = [];

    try {
      // Load the app file as ZIP
      this.zip = await JSZip.loadAsync(this.fileBuffer);

      if (this.platform === 'android') {
        await this.scanAndroidApp();
      } else {
        await this.scanIOSApp();
      }
    } catch (error) {
      console.error('Mobile scan error:', error);
      throw error;
    }

    return {
      vulnerabilities: this.vulnerabilities,
      metadata: this.appMetadata,
    };
  }

  private async scanAndroidApp(): Promise<void> {
    if (!this.zip) return;

    // Extract AndroidManifest.xml
    const manifestFile = this.zip.file('AndroidManifest.xml');
    let manifest: any = null;

    if (manifestFile) {
      try {
        const manifestContent = await manifestFile.async('text');
        manifest = await this.parseXML(manifestContent);
        
        // Extract app metadata
        if (manifest?.manifest) {
          this.appMetadata.packageName = manifest.manifest.$?.package || '';
          this.appMetadata.version = manifest.manifest.$?.['android:versionName'] || manifest.manifest.$?.['android:versionCode'] || '';
          this.appMetadata.appName = this.appMetadata.packageName.split('.').pop() || this.fileName;
        }
      } catch (error) {
        console.error('Error parsing AndroidManifest.xml:', error);
      }
    }

    // OWASP Mobile Top 10 Checks for Android
    await this.checkM1ImproperPlatformUsage(manifest);
    await this.checkM2InsecureDataStorage();
    await this.checkM3InsecureCommunication();
    await this.checkM4InsecureAuthentication();
    await this.checkM5InsufficientCryptography();
    await this.checkM6InsecureAuthorization();
    await this.checkM7ClientCodeQuality();
    await this.checkM8CodeTampering();
    await this.checkM9ReverseEngineering();
    await this.checkM10ExtraneousFunctionality();

    // Android-specific checks
    await this.checkAndroidPermissions(manifest);
    await this.checkAndroidBackupEnabled(manifest);
    await this.checkAndroidDebuggable(manifest);
    await this.checkAndroidExportedComponents(manifest);
  }

  private async scanIOSApp(): Promise<void> {
    if (!this.zip) return;

    // Extract Info.plist
    const plistFiles = Object.keys(this.zip.files).filter(f => f.endsWith('Info.plist'));
    let plist: any = null;

    if (plistFiles.length > 0) {
      try {
        const plistContent = await this.zip.file(plistFiles[0])?.async('text');
        if (plistContent) {
          plist = parsePlist(plistContent);
          
          this.appMetadata.appName = plist.CFBundleName || plist.CFBundleDisplayName || this.fileName;
          this.appMetadata.packageName = plist.CFBundleIdentifier || '';
          this.appMetadata.version = plist.CFBundleShortVersionString || plist.CFBundleVersion || '';
        }
      } catch (error) {
        console.error('Error parsing Info.plist:', error);
      }
    }

    // OWASP Mobile Top 10 Checks for iOS
    await this.checkM1ImproperPlatformUsage(plist);
    await this.checkM2InsecureDataStorage();
    await this.checkM3InsecureCommunication();
    await this.checkM4InsecureAuthentication();
    await this.checkM5InsufficientCryptography();
    await this.checkM6InsecureAuthorization();
    await this.checkM7ClientCodeQuality();
    await this.checkM8CodeTampering();
    await this.checkM9ReverseEngineering();
    await this.checkM10ExtraneousFunctionality();

    // iOS-specific checks
    await this.checkIOSATSSettings(plist);
    await this.checkIOSURLSchemes(plist);
    await this.checkIOSBackgroundModes(plist);
  }

  // OWASP Mobile Top 10 Checks

  private async checkM1ImproperPlatformUsage(config: any): Promise<void> {
    if (this.platform === 'android' && config?.manifest) {
      const minSdkVersion = config.manifest['uses-sdk']?.[0]?.$?.['android:minSdkVersion'];
      
      if (minSdkVersion && parseInt(minSdkVersion) < 23) {
        this.vulnerabilities.push({
          title: 'M1: Outdated Platform Version Support',
          description: `The application supports Android API level ${minSdkVersion}, which lacks modern security features and contains known vulnerabilities. Supporting outdated platforms exposes users to security risks.`,
          severity: 'high',
          owasp_category: 'M1: Improper Platform Usage',
          cvss_score: 7.5,
          cwe_id: 'CWE-1329',
          recommendation: 'Increase minSdkVersion to at least API 23 (Android 6.0) or higher. Remove support for legacy platforms that lack modern security controls.',
          evidence: `minSdkVersion="${minSdkVersion}" in AndroidManifest.xml`,
          file_path: 'AndroidManifest.xml',
        });
      }

      // Check for deprecated features
      const usesFeatures = config.manifest['uses-feature'] || [];
      const hasDeprecated = usesFeatures.some((f: any) => 
        f.$?.['android:name']?.includes('android.hardware.telephony')
      );

      if (hasDeprecated) {
        this.vulnerabilities.push({
          title: 'M1: Usage of Deprecated Platform Features',
          description: 'The application uses deprecated platform features that may have security implications or be removed in future versions.',
          severity: 'low',
          owasp_category: 'M1: Improper Platform Usage',
          cvss_score: 3.0,
          recommendation: 'Review and update deprecated features to use modern alternatives.',
          evidence: 'Deprecated features detected in manifest',
          file_path: 'AndroidManifest.xml',
        });
      }
    }

    if (this.platform === 'ios' && config) {
      const minVersion = config.MinimumOSVersion;
      if (minVersion && parseFloat(minVersion) < 12.0) {
        this.vulnerabilities.push({
          title: 'M1: Outdated iOS Version Support',
          description: `The application supports iOS ${minVersion}, which contains known security vulnerabilities and lacks modern security features.`,
          severity: 'high',
          owasp_category: 'M1: Improper Platform Usage',
          cvss_score: 7.5,
          cwe_id: 'CWE-1329',
          recommendation: 'Increase MinimumOSVersion to at least iOS 12.0 or higher.',
          evidence: `MinimumOSVersion="${minVersion}" in Info.plist`,
          file_path: 'Info.plist',
        });
      }
    }
  }

  private async checkM2InsecureDataStorage(): Promise<void> {
    if (!this.zip) return;

    // Check for hardcoded database files
    const dbFiles = Object.keys(this.zip.files).filter(f => 
      f.endsWith('.db') || f.endsWith('.sqlite') || f.endsWith('.realm')
    );

    if (dbFiles.length > 0) {
      this.vulnerabilities.push({
        title: 'M2: Unencrypted Local Database Detected',
        description: 'The application contains database files that may store sensitive data without encryption. This data could be accessed by malicious apps or through device backup.',
        severity: 'high',
        owasp_category: 'M2: Insecure Data Storage',
        cvss_score: 7.2,
        cwe_id: 'CWE-312',
        recommendation: 'Encrypt all local databases using SQLCipher or platform-specific encryption APIs. Use Android Keystore or iOS Keychain for encryption keys.',
        evidence: `Found ${dbFiles.length} database file(s): ${dbFiles.slice(0, 3).join(', ')}`,
        file_path: dbFiles[0],
      });
    }

    // Check for shared preferences (Android) or plist files
    const prefFiles = Object.keys(this.zip.files).filter(f => 
      f.endsWith('shared_prefs.xml') || f.includes('preferences')
    );

    if (prefFiles.length > 0) {
      this.vulnerabilities.push({
        title: 'M2: Potentially Insecure Shared Preferences',
        description: 'The application uses shared preferences which may store sensitive data in plaintext. These files are accessible through device backup and rooted devices.',
        severity: 'medium',
        owasp_category: 'M2: Insecure Data Storage',
        cvss_score: 5.5,
        cwe_id: 'CWE-312',
        recommendation: 'Use EncryptedSharedPreferences (Android) or Keychain (iOS) for sensitive data. Never store passwords, tokens, or encryption keys in plain text.',
        evidence: `Found preference files: ${prefFiles.slice(0, 2).join(', ')}`,
      });
    }

    // Check for log files
    const logFiles = Object.keys(this.zip.files).filter(f => 
      f.endsWith('.log') || f.endsWith('.txt')
    );

    if (logFiles.length > 5) {
      this.vulnerabilities.push({
        title: 'M2: Excessive Logging Detected',
        description: 'Multiple log files detected in the application bundle. Logs may contain sensitive information that persists on the device.',
        severity: 'low',
        owasp_category: 'M2: Insecure Data Storage',
        cvss_score: 3.5,
        cwe_id: 'CWE-532',
        recommendation: 'Disable verbose logging in production builds. Ensure logs don\'t contain sensitive data. Use ProGuard/R8 to strip logging code.',
        evidence: `Found ${logFiles.length} log files`,
      });
    }
  }

  private async checkM3InsecureCommunication(): Promise<void> {
    if (!this.zip) return;

    // Search for HTTP URLs in code
    const codeFiles = Object.keys(this.zip.files).filter(f => 
      f.endsWith('.dex') || f.endsWith('.jar') || f.endsWith('.class') || f.includes('classes')
    );

    for (const file of codeFiles.slice(0, 10)) {
      const content = await this.zip.file(file)?.async('text').catch(() => '');
      
      if (content && content.includes('http://') && !content.includes('localhost')) {
        this.vulnerabilities.push({
          title: 'M3: Insecure HTTP Communication',
          description: 'The application contains HTTP URLs, indicating unencrypted network communication. This exposes data to man-in-the-middle attacks and eavesdropping.',
          severity: 'high',
          owasp_category: 'M3: Insecure Communication',
          cvss_score: 7.4,
          cwe_id: 'CWE-319',
          recommendation: 'Use HTTPS for all network communication. Implement certificate pinning for critical connections. Enable Network Security Configuration (Android) or App Transport Security (iOS).',
          evidence: 'HTTP URLs detected in application code',
          file_path: file,
        });
        break;
      }
    }

    // Check for weak SSL/TLS implementations
    const hasWeakCrypto = await this.searchInCode([
      'TrustAllCertificates', 
      'SSLv3',
      'TLSv1.0',
      'ALLOW_ALL_HOSTNAME_VERIFIER',
      'X509TrustManager'
    ]);

    if (hasWeakCrypto.found) {
      this.vulnerabilities.push({
        title: 'M3: Weak SSL/TLS Implementation',
        description: 'The application may disable certificate validation or use weak SSL/TLS configurations, making it vulnerable to man-in-the-middle attacks.',
        severity: 'critical',
        owasp_category: 'M3: Insecure Communication',
        cvss_score: 9.1,
        cwe_id: 'CWE-295',
        recommendation: 'Never disable certificate validation. Use strong TLS versions (1.2+). Implement certificate pinning. Properly validate SSL certificates.',
        evidence: hasWeakCrypto.evidence,
        file_path: hasWeakCrypto.file,
      });
    }
  }

  private async checkM4InsecureAuthentication(): Promise<void> {
    // Check for hardcoded credentials
    const credentials = await this.searchInCode([
      'password', 'passwd', 'pwd', 'api_key', 'apikey', 'secret', 'token',
      'auth_token', 'access_token', 'private_key'
    ]);

    if (credentials.found) {
      this.vulnerabilities.push({
        title: 'M4: Hardcoded Credentials Detected',
        description: 'The application contains hardcoded credentials or API keys. These can be easily extracted through reverse engineering and used by attackers.',
        severity: 'critical',
        owasp_category: 'M4: Insecure Authentication',
        cvss_score: 9.8,
        cwe_id: 'CWE-798',
        recommendation: 'Never hardcode credentials in the application. Use secure token storage (Keychain/Keystore). Implement proper authentication flows with backend validation.',
        evidence: credentials.evidence,
        file_path: credentials.file,
        code_snippet: credentials.snippet,
      });
    }

    // Check for biometric authentication issues
    const biometric = await this.searchInCode([
      'BiometricPrompt',
      'FingerprintManager',
      'TouchID',
      'FaceID'
    ]);

    if (biometric.found) {
      this.vulnerabilities.push({
        title: 'M4: Biometric Authentication Implementation',
        description: 'The application uses biometric authentication. Ensure it\'s implemented securely as a convenience factor, not the sole authentication method.',
        severity: 'info',
        owasp_category: 'M4: Insecure Authentication',
        recommendation: 'Use biometrics only after proper server-side authentication. Store authentication state securely. Implement fallback authentication. Require re-authentication for sensitive operations.',
        evidence: 'Biometric authentication APIs detected',
      });
    }
  }

  private async checkM5InsufficientCryptography(): Promise<void> {
    // Check for weak encryption algorithms
    const weakCrypto = await this.searchInCode([
      'DES', 'RC4', 'MD5', 'SHA1', 'ECB',
      'NoPadding', 'insecure', 'Random()'
    ]);

    if (weakCrypto.found) {
      this.vulnerabilities.push({
        title: 'M5: Weak Cryptographic Algorithms',
        description: 'The application uses weak or broken cryptographic algorithms that can be easily broken by attackers, compromising data confidentiality.',
        severity: 'high',
        owasp_category: 'M5: Insufficient Cryptography',
        cvss_score: 7.5,
        cwe_id: 'CWE-327',
        recommendation: 'Use strong cryptographic algorithms: AES-256 for encryption, SHA-256 for hashing, RSA 2048+ for asymmetric crypto. Use SecureRandom for key generation. Avoid ECB mode.',
        evidence: weakCrypto.evidence,
        file_path: weakCrypto.file,
      });
    }

    // Check for static encryption keys
    const staticKeys = await this.searchInCode([
      'static final byte[] KEY',
      'private static final String KEY',
      'let encryptionKey =',
      'const encryptionKey'
    ]);

    if (staticKeys.found) {
      this.vulnerabilities.push({
        title: 'M5: Hardcoded Encryption Keys',
        description: 'The application contains hardcoded encryption keys. These keys can be extracted and used to decrypt sensitive data.',
        severity: 'critical',
        owasp_category: 'M5: Insufficient Cryptography',
        cvss_score: 9.1,
        cwe_id: 'CWE-321',
        recommendation: 'Generate encryption keys dynamically using secure random number generators. Store keys in Android Keystore or iOS Keychain. Derive keys from user passwords using PBKDF2.',
        evidence: staticKeys.evidence,
        file_path: staticKeys.file,
      });
    }
  }

  private async checkM6InsecureAuthorization(): Promise<void> {
    // Check for client-side authorization
    const authChecks = await this.searchInCode([
      'isAdmin', 'isRoot', 'hasPermission', 'canAccess',
      'role == ', 'userType ==', 'accessLevel'
    ]);

    if (authChecks.found) {
      this.vulnerabilities.push({
        title: 'M6: Potential Client-Side Authorization',
        description: 'The application appears to perform authorization checks on the client side. These can be easily bypassed through code modification or runtime manipulation.',
        severity: 'high',
        owasp_category: 'M6: Insecure Authorization',
        cvss_score: 7.5,
        cwe_id: 'CWE-602',
        recommendation: 'Perform all authorization checks on the server side. Never trust client-side decisions. Implement proper role-based access control (RBAC) on the backend.',
        evidence: authChecks.evidence,
        file_path: authChecks.file,
      });
    }

    // Check for insecure deep links
    const deepLinks = await this.searchInCode([
      'intent-filter', 'scheme://', 'URL scheme',
      'handleOpenURL', 'openURL'
    ]);

    if (deepLinks.found) {
      this.vulnerabilities.push({
        title: 'M6: Insecure Deep Link Handling',
        description: 'The application handles deep links which can be exploited for unauthorized access or phishing if not properly validated.',
        severity: 'medium',
        owasp_category: 'M6: Insecure Authorization',
        cvss_score: 6.5,
        cwe_id: 'CWE-939',
        recommendation: 'Validate all deep link parameters. Require authentication for sensitive actions. Use app links with domain verification. Sanitize input from deep links.',
        evidence: 'Deep link handling detected',
      });
    }
  }

  private async checkM7ClientCodeQuality(): Promise<void> {
    // Check for buffer overflow risks
    const bufferIssues = await this.searchInCode([
      'strcpy', 'sprintf', 'gets', 'memcpy',
      'UnsafePointer', 'malloc', 'free'
    ]);

    if (bufferIssues.found) {
      this.vulnerabilities.push({
        title: 'M7: Unsafe Memory Operations',
        description: 'The application uses unsafe memory operations that could lead to buffer overflows, crashes, or code execution vulnerabilities.',
        severity: 'high',
        owasp_category: 'M7: Client Code Quality',
        cvss_score: 7.8,
        cwe_id: 'CWE-120',
        recommendation: 'Use safe string functions (strncpy, snprintf). Validate buffer sizes. Use memory-safe languages and libraries. Enable compiler security features.',
        evidence: bufferIssues.evidence,
      });
    }

    // Check for SQL injection in mobile code
    const sqlInjection = await this.searchInCode([
      'execSQL', 'rawQuery', 'SQLiteDatabase',
      'SELECT * FROM', 'WHERE.*=.*+'
    ]);

    if (sqlInjection.found) {
      this.vulnerabilities.push({
        title: 'M7: Potential SQL Injection in Local Database',
        description: 'The application may construct SQL queries using string concatenation, which could lead to SQL injection vulnerabilities in the local database.',
        severity: 'medium',
        owasp_category: 'M7: Client Code Quality',
        cvss_score: 5.5,
        cwe_id: 'CWE-89',
        recommendation: 'Use parameterized queries with prepared statements. Never concatenate user input into SQL queries. Use ORM frameworks with built-in protection.',
        evidence: 'Dynamic SQL query construction detected',
      });
    }
  }

  private async checkM8CodeTampering(): Promise<void> {
    // Check for root/jailbreak detection
    const rootDetection = await this.searchInCode([
      'RootBeer', 'isRooted', 'isJailbroken',
      '/system/app/Superuser.apk', 'cydia://'
    ]);

    if (!rootDetection.found) {
      this.vulnerabilities.push({
        title: 'M8: Missing Root/Jailbreak Detection',
        description: 'The application does not implement root or jailbreak detection. Rooted/jailbroken devices bypass security controls and allow code tampering.',
        severity: 'medium',
        owasp_category: 'M8: Code Tampering',
        cvss_score: 6.0,
        cwe_id: 'CWE-353',
        recommendation: 'Implement root/jailbreak detection. Warn users or limit functionality on compromised devices. Use SafetyNet Attestation (Android) or DeviceCheck (iOS).',
        evidence: 'No root/jailbreak detection mechanisms found',
      });
    }

    // Check for integrity verification
    const integrityCheck = await this.searchInCode([
      'checkSignature', 'PackageManager.GET_SIGNATURES',
      'verifyChecksum', 'hashCode'
    ]);

    if (!integrityCheck.found) {
      this.vulnerabilities.push({
        title: 'M8: Missing Code Integrity Checks',
        description: 'The application does not verify its own integrity, making it easier for attackers to modify the app and bypass security controls.',
        severity: 'medium',
        owasp_category: 'M8: Code Tampering',
        cvss_score: 5.5,
        cwe_id: 'CWE-353',
        recommendation: 'Implement runtime integrity checks. Verify app signature. Use Google Play App Signing. Detect and respond to code modifications.',
        evidence: 'No code integrity verification found',
      });
    }
  }

  private async checkM9ReverseEngineering(): Promise<void> {
    if (this.platform === 'android') {
      // Check for ProGuard/R8 obfuscation
      const hasProGuard = Object.keys(this.zip?.files || {}).some(f => 
        f.includes('proguard') || f.includes('r8')
      );

      if (!hasProGuard) {
        this.vulnerabilities.push({
          title: 'M9: Missing Code Obfuscation',
          description: 'The application does not appear to use code obfuscation (ProGuard/R8). This makes reverse engineering trivial and exposes business logic and algorithms.',
          severity: 'medium',
          owasp_category: 'M9: Reverse Engineering',
          cvss_score: 5.3,
          cwe_id: 'CWE-656',
          recommendation: 'Enable ProGuard or R8 obfuscation in release builds. Use string encryption. Apply multiple layers of obfuscation. Consider native code for sensitive logic.',
          evidence: 'No obfuscation detected in APK',
        });
      }

      // Check for native libraries
      const nativeLibs = Object.keys(this.zip?.files || {}).filter(f => 
        f.endsWith('.so')
      );

      if (nativeLibs.length > 0) {
        this.vulnerabilities.push({
          title: 'M9: Native Libraries Require Additional Protection',
          description: 'The application includes native libraries which can be reverse engineered using tools like IDA Pro or Ghidra.',
          severity: 'info',
          owasp_category: 'M9: Reverse Engineering',
          recommendation: 'Strip symbols from native libraries. Use control flow obfuscation. Implement anti-debugging techniques. Consider commercial obfuscation tools.',
          evidence: `Found ${nativeLibs.length} native library(ies)`,
        });
      }
    }

    // Check for debugging capabilities
    const debugCode = await this.searchInCode([
      'BuildConfig.DEBUG', 'Log.d', 'Log.v',
      'NSLog', 'print(', 'console.log'
    ]);

    if (debugCode.found) {
      this.vulnerabilities.push({
        title: 'M9: Debug Code in Production',
        description: 'The application contains debug logging code that could expose sensitive information and assist attackers in reverse engineering.',
        severity: 'low',
        owasp_category: 'M9: Reverse Engineering',
        cvss_score: 3.3,
        cwe_id: 'CWE-489',
        recommendation: 'Remove all debug code from production builds. Use conditional compilation. Strip logging statements during build process.',
        evidence: 'Debug logging detected in application code',
      });
    }
  }

  private async checkM10ExtraneousFunctionality(): Promise<void> {
    // Check for test/debug endpoints
    const testCode = await this.searchInCode([
      'test', 'debug', 'staging', 'dev',
      'BuildConfig.BUILD_TYPE', 'DEBUG_MODE'
    ]);

    if (testCode.found) {
      this.vulnerabilities.push({
        title: 'M10: Test/Debug Functionality Detected',
        description: 'The application may contain test or debug functionality that could be exploited by attackers to bypass security controls or access sensitive features.',
        severity: 'medium',
        owasp_category: 'M10: Extraneous Functionality',
        cvss_score: 5.3,
        cwe_id: 'CWE-489',
        recommendation: 'Remove all test and debug code from production builds. Use separate build variants. Disable test endpoints in production. Remove development credentials.',
        evidence: 'Test/debug code detected',
      });
    }

    // Check for admin/hidden features
    const hiddenFeatures = await this.searchInCode([
      'admin', 'backdoor', 'hidden', 'secret',
      'super_user', 'god_mode'
    ]);

    if (hiddenFeatures.found) {
      this.vulnerabilities.push({
        title: 'M10: Potential Hidden Functionality',
        description: 'The application contains references to admin, hidden, or backdoor functionality that could provide unauthorized access.',
        severity: 'high',
        owasp_category: 'M10: Extraneous Functionality',
        cvss_score: 7.5,
        cwe_id: 'CWE-912',
        recommendation: 'Remove all hidden functionality and backdoors. Implement proper admin controls on the server side. Use feature flags for beta features.',
        evidence: hiddenFeatures.evidence,
        file_path: hiddenFeatures.file,
      });
    }
  }

  // Platform-specific checks

  private async checkAndroidPermissions(manifest: any): Promise<void> {
    if (!manifest?.manifest) return;

    const permissions = manifest.manifest['uses-permission'] || [];
    const dangerousPermissions = [
      'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
      'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
      'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'
    ];

    const requestedDangerous = permissions
      .map((p: any) => p.$?.['android:name']?.split('.').pop())
      .filter((p: string) => dangerousPermissions.includes(p));

    if (requestedDangerous.length > 3) {
      this.vulnerabilities.push({
        title: 'Excessive Dangerous Permissions',
        description: `The application requests ${requestedDangerous.length} dangerous permissions. Each permission increases the attack surface and privacy concerns.`,
        severity: 'medium',
        owasp_category: 'M1: Improper Platform Usage',
        cvss_score: 5.0,
        recommendation: 'Request only necessary permissions. Use runtime permissions. Explain why each permission is needed. Consider alternatives to dangerous permissions.',
        evidence: `Dangerous permissions: ${requestedDangerous.join(', ')}`,
        file_path: 'AndroidManifest.xml',
      });
    }
  }

  private async checkAndroidBackupEnabled(manifest: any): Promise<void> {
    if (!manifest?.manifest?.application?.[0]) return;

    const allowBackup = manifest.manifest.application[0].$?.['android:allowBackup'];
    
    if (allowBackup === 'true' || allowBackup === undefined) {
      this.vulnerabilities.push({
        title: 'Android Backup Enabled',
        description: 'The application allows backup via adb or cloud services. This could expose sensitive data stored by the app.',
        severity: 'medium',
        owasp_category: 'M2: Insecure Data Storage',
        cvss_score: 5.5,
        cwe_id: 'CWE-530',
        recommendation: 'Set android:allowBackup="false" or implement backup rules to exclude sensitive data. Use BackupAgent for controlled backups.',
        evidence: 'android:allowBackup not disabled in AndroidManifest.xml',
        file_path: 'AndroidManifest.xml',
      });
    }
  }

  private async checkAndroidDebuggable(manifest: any): Promise<void> {
    if (!manifest?.manifest?.application?.[0]) return;

    const debuggable = manifest.manifest.application[0].$?.['android:debuggable'];
    
    if (debuggable === 'true') {
      this.vulnerabilities.push({
        title: 'Application Debuggable in Production',
        description: 'The application is marked as debuggable, allowing attackers to attach debuggers and inspect runtime behavior, memory, and intercept data.',
        severity: 'critical',
        owasp_category: 'M8: Code Tampering',
        cvss_score: 9.0,
        cwe_id: 'CWE-489',
        recommendation: 'Remove android:debuggable="true" from production builds. Ensure release builds are not debuggable.',
        evidence: 'android:debuggable="true" in AndroidManifest.xml',
        file_path: 'AndroidManifest.xml',
      });
    }
  }

  private async checkAndroidExportedComponents(manifest: any): Promise<void> {
    if (!manifest?.manifest?.application?.[0]) return;

    const app = manifest.manifest.application[0];
    const activities = app.activity || [];
    const services = app.service || [];
    const receivers = app.receiver || [];

    const exportedComponents = [
      ...activities.filter((a: any) => a.$?.['android:exported'] === 'true'),
      ...services.filter((s: any) => s.$?.['android:exported'] === 'true'),
      ...receivers.filter((r: any) => r.$?.['android:exported'] === 'true'),
    ];

    if (exportedComponents.length > 2) {
      this.vulnerabilities.push({
        title: 'Excessive Exported Components',
        description: `The application has ${exportedComponents.length} exported components that can be accessed by other applications. This increases the attack surface.`,
        severity: 'medium',
        owasp_category: 'M6: Insecure Authorization',
        cvss_score: 5.3,
        cwe_id: 'CWE-927',
        recommendation: 'Set android:exported="false" for components that don\'t need to be public. Add permission checks to exported components. Validate all intents.',
        evidence: `${exportedComponents.length} exported components in AndroidManifest.xml`,
        file_path: 'AndroidManifest.xml',
      });
    }
  }

  private async checkIOSATSSettings(plist: any): Promise<void> {
    if (!plist) return;

    const ats = plist.NSAppTransportSecurity;
    
    if (ats?.NSAllowsArbitraryLoads === true) {
      this.vulnerabilities.push({
        title: 'App Transport Security Disabled',
        description: 'App Transport Security (ATS) is disabled, allowing insecure HTTP connections. This exposes network communication to interception and tampering.',
        severity: 'high',
        owasp_category: 'M3: Insecure Communication',
        cvss_score: 7.4,
        cwe_id: 'CWE-319',
        recommendation: 'Enable ATS and use HTTPS for all connections. If HTTP is required, use exception domains instead of NSAllowsArbitraryLoads.',
        evidence: 'NSAllowsArbitraryLoads=true in Info.plist',
        file_path: 'Info.plist',
      });
    }
  }

  private async checkIOSURLSchemes(plist: any): Promise<void> {
    if (!plist) return;

    const urlSchemes = plist.CFBundleURLTypes;
    
    if (urlSchemes && urlSchemes.length > 0) {
      this.vulnerabilities.push({
        title: 'Custom URL Schemes Detected',
        description: 'The application registers custom URL schemes which can be exploited for deep link attacks if not properly validated.',
        severity: 'medium',
        owasp_category: 'M6: Insecure Authorization',
        cvss_score: 5.3,
        cwe_id: 'CWE-939',
        recommendation: 'Validate all URL scheme parameters. Use Universal Links instead of custom URL schemes. Implement proper authentication for sensitive actions.',
        evidence: `Found ${urlSchemes.length} custom URL scheme(s)`,
        file_path: 'Info.plist',
      });
    }
  }

  private async checkIOSBackgroundModes(plist: any): Promise<void> {
    if (!plist) return;

    const backgroundModes = plist.UIBackgroundModes;
    
    if (backgroundModes && backgroundModes.length > 2) {
      this.vulnerabilities.push({
        title: 'Excessive Background Modes',
        description: `The application requests ${backgroundModes.length} background modes. Unnecessary background execution increases battery drain and privacy concerns.`,
        severity: 'low',
        owasp_category: 'M1: Improper Platform Usage',
        cvss_score: 3.0,
        recommendation: 'Request only necessary background modes. Document why each mode is needed. Minimize background activity.',
        evidence: `Background modes: ${backgroundModes.join(', ')}`,
        file_path: 'Info.plist',
      });
    }
  }

  // Helper methods

  private async searchInCode(patterns: string[]): Promise<{ found: boolean; evidence: string; file?: string; snippet?: string }> {
    if (!this.zip) return { found: false, evidence: '' };

    const searchFiles = Object.keys(this.zip.files).filter(f => 
      f.endsWith('.dex') || f.endsWith('.class') || f.endsWith('.jar') ||
      f.endsWith('.js') || f.endsWith('.m') || f.endsWith('.swift') ||
      f.endsWith('.xml') || f.endsWith('.json') || f.endsWith('.plist')
    );

    for (const file of searchFiles.slice(0, 20)) {
      try {
        const content = await this.zip.file(file)?.async('text').catch(() => '');
        
        for (const pattern of patterns) {
          if (content && content.toLowerCase().includes(pattern.toLowerCase())) {
            const lines = content.split('\n');
            const lineIndex = lines.findIndex(line => line.toLowerCase().includes(pattern.toLowerCase()));
            const snippet = lineIndex >= 0 ? lines.slice(Math.max(0, lineIndex - 1), lineIndex + 2).join('\n') : '';
            
            return {
              found: true,
              evidence: `Pattern "${pattern}" found in application code`,
              file,
              snippet: snippet.substring(0, 200),
            };
          }
        }
      } catch (error) {
        // Skip files that can't be read
      }
    }

    return { found: false, evidence: '' };
  }

  private parseXML(xml: string): Promise<any> {
    return new Promise((resolve, reject) => {
      parseString(xml, (err: Error | null, result: any) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }
}
