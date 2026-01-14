import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { cors } from "hono/cors";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { CreateScanSchema } from "../shared/types";
import { SecurityScanner, CWETop25Scanner, NISTSP800171Scanner } from "./scanner";
import { MobileSecurityScanner } from "./mobile-scanner";
// import { ReportGenerator } from "./report-generator";
// import { MobileReportGenerator } from "./mobile-report-generator";
// import * as wranglerConfig from "../../wrangler.json"; // Removed for Netlify compatibility

// Define the Env interface to include Supabase vars
type Env = {
  SUPABASE_URL?: string;
  SUPABASE_KEY?: string;
};

// Some mobile scan fields (e.g., evidence, code snippets) can contain null bytes,
// which Postgres text columns do not support. This helper strips \u0000 safely.
const sanitizeText = (value: string | null | undefined): string | null => {
  if (!value) return null;
  return value.replace(/\u0000/g, "");
};

// Maximum allowed upload size for mobile scans (in bytes)
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB — adjust as needed

// Sanitize filename before storing in file_key (keep it safe and limited)
const sanitizeFileName = (name: string): string => {
  // keep letters, numbers, dot, underscore, dash; replace others with underscore; limit length
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 255);
};

const app = new Hono<{ Bindings: Env }>();

app.use("/*", cors());

// Global error handler to prevent 502/crashes
app.onError((err, c) => {
  console.error("Global App Error:", err);
  return c.json({
    error: "Internal Server Error",
    message: err.message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined
  }, 500);
});

// Polyfill helper for executionCtx.waitUntil (missing in Netlify)
const safeWaitUntil = (c: any, promise: Promise<void>) => {
  if (c.executionCtx && typeof c.executionCtx.waitUntil === 'function') {
    c.executionCtx.waitUntil(promise);
  } else {
    // In Netlify/Node, we don't have waitUntil.
    // Ensure we catch errors so unhandled promises don't crash the process
    promise.catch(err => console.error("Async background task error:", err));
  }
};

// Helper to get Supabase client with fallback to process.env
const getSupabase = (env: Env): SupabaseClient => {
  // Check Hono env (Cloudflare), then process.env (Netlify/Node)
  const supabaseUrl = env?.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
  const supabaseKey = env?.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

  if (!supabaseUrl || !supabaseKey) {
    throw new Error("Supabase URL and Key must be configured. Check environment variables.");
  }

  return createClient(supabaseUrl, supabaseKey);
};

// Helper: extract userId from Authorization header
const getUserIdFromRequest = async (c: any): Promise<string | null> => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader) return null;

  try {
    const token = authHeader.replace("Bearer ", "");
    // Check Hono env, then process.env
    const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
    const supabaseAnonKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

    if (!supabaseUrl || !supabaseAnonKey) return null;

    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    });

    const {
      data: { user },
      error: userError,
    } = await userClient.auth.getUser(token);

    if (!userError && user) {
      return user.id;
    }
  } catch (err) {
    console.warn("Failed to extract user from token in getUserIdFromRequest:", err);
  }

  return null;
};

// Get all scans (scoped to current user)
app.get("/api/scans", async (c) => {
  const supabase = getSupabase(c.env);
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Get a single scan (scoped to current user)
app.get("/api/scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .eq("id", id)
    .eq("user_id", userId)
    .single();

  if (error || !data) return c.json({ error: "Scan not found" }, 404);
  return c.json(data);
});

// Get vulnerabilities for a scan (scoped to current user)
app.get("/api/scans/:id/vulnerabilities", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Optional: ensure scan belongs to user
  const { data: scan, error: scanError } = await supabase
    .from("scans")
    .select("id")
    .eq("id", id)
    .eq("user_id", userId)
    .maybeSingle();

  if (scanError || !scan) {
    return c.json({ error: "Scan not found" }, 404);
  }

  const { data, error } = await supabase
    .from("web_vulnerabilities")
    .select("*")
    .eq("scan_id", id)
    .order("created_at", { ascending: false }); // Simple ordering by date

  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Create a new scan
app.post("/api/scans", zValidator("json", CreateScanSchema), async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const data = c.req.valid("json");

    // Extract user_id from auth token
    let userId: string | null = null;
    const authHeader = c.req.header("Authorization");
    if (authHeader) {
      try {
        const token = authHeader.replace("Bearer ", "");
        const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
        const supabaseAnonKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

        if (supabaseUrl && supabaseAnonKey) {
          // Create a Supabase client with anon key and user's token
          const userClient = createClient(supabaseUrl, supabaseAnonKey, {
            global: {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            },
          });
          const { data: { user }, error: userError } = await userClient.auth.getUser(token);
          if (!userError && user) {
            userId = user.id;
          }
        }
      } catch (err) {
        console.warn("Failed to extract user from token:", err);
        // Continue without user_id if token is invalid
      }
    }

    // Helper to check if error is internal
    const isInternalError = (err: any): boolean => {
      const msg = err?.message || err?.details || String(err || '');
      return msg.includes('internal error') || msg.includes('reference =');
    };

    // Create scan record with retry logic
    let scan: any = null;
    let lastError: any = null;

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        if (attempt > 0) {
          // Wait before retry
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        const insertData: any = {
          target_url: data.target_url,
          scan_type: data.scan_type,
          status: "running",
          started_at: new Date().toISOString()
        };

        // Add user_id if available
        if (userId) {
          insertData.user_id = userId;
        }

        const result = await supabase
          .from("scans")
          .insert(insertData)
          .select()
          .single();

        if (result.error) {
          lastError = result.error;
          // If it's an internal error and we haven't retried yet, retry
          if (isInternalError(result.error) && attempt === 0) {
            continue;
          }
          // Otherwise, return the error
          throw result.error;
        }

        if (!result.data) {
          throw new Error("No data returned from database");
        }

        scan = result.data;
        break; // Success, exit retry loop

      } catch (err: any) {
        lastError = err;
        // If it's an internal error and we haven't retried yet, retry
        if (isInternalError(err) && attempt === 0) {
          continue;
        }
        // Otherwise, throw to be caught by outer catch
        throw err;
      }
    }

    if (!scan) {
      return c.json({
        error: "Database temporarily unavailable. Please try again in a moment.",
        details: lastError?.message || 'Unknown error'
      }, 503);
    }

    const scanId = scan.id;

    // Run scan asynchronously
    safeWaitUntil(c,
      (async () => {
        // Re-initialize supabase inside async context to be safe
        const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
        const supabaseKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);
        if (!supabaseUrl || !supabaseKey) {
          console.error("Supabase credentials not available");
          return;
        }
        const sb = createClient(supabaseUrl, supabaseKey);

        try {
          // Run all scanners in parallel
          const [standardVulns, cweTop25Results, nistResults] = await Promise.all([
            // Standard Security Scanner
            (async () => {
              const scanner = new SecurityScanner({
                targetUrl: data.target_url,
                scanType: data.scan_type,
              });
              return await scanner.scan();
            })(),
            // CWE Top 25 Scanner
            (async () => {
              try {
                const cweScanner = new CWETop25Scanner({
                  targetUrl: data.target_url,
                });
                return await cweScanner.scan();
              } catch (error) {
                console.warn("CWE Top 25 scanner failed:", error);
                return [];
              }
            })(),
            // NIST SP 800-171 Compliance Scanner
            (async () => {
              try {
                const nistScanner = new NISTSP800171Scanner({
                  targetUrl: data.target_url,
                });
                return await nistScanner.scan();
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                console.warn(`[Scan ${scanId}] NIST SP 800-171 scanner failed for ${data.target_url}:`, errorMessage);
                // Log full error details for debugging
                if (error instanceof Error) {
                  console.warn(`[Scan ${scanId}] NIST scanner error stack:`, error.stack);
                }
                return [];
              }
            })()
          ]);

          // Convert CWE Top 25 results to VulnerabilityResult format
          const cweVulns = cweTop25Results
            .filter(result => result.detected) // Only include detected vulnerabilities
            .map(result => ({
              title: `${result.name} (CWE Top 25 #${result.rank})`,
              description: result.description,
              severity: result.severity as "critical" | "high" | "medium" | "low" | "info",
              category: `CWE Top 25 - Rank ${result.rank}`,
              cvss_score: result.score,
              cwe_id: result.cwe_id,
              recommendation: result.recommendation,
              evidence: result.evidence || `CWE Top 25 vulnerability detected. Impact: ${result.impact}. Platforms: ${result.platforms.join(', ')}.`,
              scannerType: 'CWE_Top_25',
            }));

          // Convert NIST SP 800-171 results to VulnerabilityResult format
          const nistVulns = nistResults
            .filter(result => !result.compliant) // Only include non-compliant controls
            .map(result => ({
              title: `${result.title} (${result.control_id}) - Non-Compliant`,
              description: `${result.description}. Compliance: ${result.requirements_met}/${result.requirements_total} requirements met.`,
              severity: result.severity,
              category: `NIST SP 800-171 - ${result.category}`,
              cvss_score: result.severity === 'critical' ? 9.0 : result.severity === 'high' ? 7.0 : result.severity === 'medium' ? 5.0 : 3.0,
              cwe_id: null,
              recommendation: result.recommendation,
              evidence: result.evidence || `NIST control ${result.control_id} non-compliance detected. ${result.requirements_met}/${result.requirements_total} requirements met.`,
              scannerType: 'NIST',
            }));

          // Add scannerType to standard vulnerabilities
          const standardVulnsWithType = standardVulns.map(vuln => ({
            ...vuln,
            scannerType: 'STANDARD' as const,
          }));

          // Combine all scanner results
          const allVulnerabilities = [...standardVulnsWithType, ...cweVulns, ...nistVulns];

          console.log(`[Scan ${scanId}] Scanner results:`, {
            standard: standardVulnsWithType.length,
            cwe: cweVulns.length,
            nist: nistVulns.length,
            total: allVulnerabilities.length
          });

          // Remove duplicates based on CWE ID and title similarity
          const uniqueVulns = allVulnerabilities.filter((vuln, index, self) => {
            // If it has a CWE ID, check for duplicates by CWE ID
            if (vuln.cwe_id) {
              const firstIndex = self.findIndex(v =>
                v.cwe_id === vuln.cwe_id &&
                v.title.toLowerCase() === vuln.title.toLowerCase()
              );
              return firstIndex === index;
            }
            // Otherwise check by title
            const firstIndex = self.findIndex(v =>
              v.title.toLowerCase() === vuln.title.toLowerCase() &&
              v.description === vuln.description
            );
            return firstIndex === index;
          });

          const vulnerabilities = uniqueVulns;

          console.log(`[Scan ${scanId}] After deduplication: ${vulnerabilities.length} unique vulnerabilities`);

          const severityCounts: Record<string, number> = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0,
          };

          // Batch insert vulnerabilities
          const vulnsToInsert = vulnerabilities.map((vuln: typeof allVulnerabilities[0]) => {
            if (severityCounts[vuln.severity] !== undefined) {
              severityCounts[vuln.severity]++;
            }
            const vulnData: any = {
              scan_id: scanId,
              title: vuln.title,
              description: vuln.description,
              severity: vuln.severity,
              category: vuln.category,
              cvss_score: vuln.cvss_score || null,
              cwe_id: vuln.cwe_id || null,
              recommendation: vuln.recommendation,
              evidence: vuln.evidence || null,
            };

            // Only add user_id and scannerType if they exist (columns might not exist in DB yet)
            if (userId) {
              vulnData.user_id = userId;
            }
            if (vuln.scannerType) {
              vulnData.scannerType = vuln.scannerType;
            }

            return vulnData;
          });

          if (vulnsToInsert.length > 0) {
            console.log(`[Scan ${scanId}] Attempting to insert ${vulnsToInsert.length} vulnerabilities into database...`);
            console.log(`[Scan ${scanId}] Sample vulnerability data:`, JSON.stringify(vulnsToInsert[0], null, 2));
            console.log(`[Scan ${scanId}] User ID:`, userId || 'null');
            console.log(`[Scan ${scanId}] Table: web_vulnerabilities`);

            // Try inserting with optional fields first, if it fails, try without them
            let vulnError: any = null;
            let insertedData: any = null;

            console.log(`[Scan ${scanId}] Inserting with all fields...`);
            const insertResult = await sb.from("web_vulnerabilities").insert(vulnsToInsert).select();
            vulnError = insertResult.error;
            insertedData = insertResult.data;

            console.log(`[Scan ${scanId}] Insert result:`, {
              error: vulnError ? vulnError.message : null,
              dataCount: insertedData?.length || 0,
              inserted: !!insertedData
            });

            // If insert failed due to missing columns, try without user_id and scannerType
            if (vulnError && (vulnError.message?.includes('column') || vulnError.message?.includes('user_id') || vulnError.message?.includes('scannerType'))) {
              console.warn(`[Scan ${scanId}] Insert failed with optional columns, retrying without user_id and scannerType...`);
              const vulnsWithoutOptional = vulnsToInsert.map(({ user_id, scannerType, ...rest }) => rest);
              const retryResult = await sb.from("web_vulnerabilities").insert(vulnsWithoutOptional).select();
              vulnError = retryResult.error;
              insertedData = retryResult.data;
              console.log(`[Scan ${scanId}] Retry result:`, {
                error: vulnError ? vulnError.message : null,
                dataCount: insertedData?.length || 0,
                inserted: !!insertedData
              });
            }

            if (vulnError) {
              console.error(`[Scan ${scanId}] Error inserting vulns:`, vulnError);
              console.error(`[Scan ${scanId}] Error details:`, JSON.stringify(vulnError, null, 2));
            } else {
              console.log(`[Scan ${scanId}] ✅ Successfully inserted ${insertedData?.length || vulnsToInsert.length} vulnerabilities`);
              const standardCount = standardVulnsWithType.length;
              const cweCount = cweVulns.length;
              const nistCount = nistVulns.length;
              console.log(`✅ Scan ${scanId} completed: Found ${vulnsToInsert.length} unique vulnerability/vulnerabilities`);
              console.log(`   - Standard Scanner: ${standardCount} vulnerabilities`);
              console.log(`   - CWE Top 25 Scanner: ${cweCount} vulnerabilities detected`);
              console.log(`   - NIST SP 800-171 Scanner: ${nistCount} non-compliant controls`);
              console.log(`   - Severity Breakdown: Critical: ${severityCounts.critical}, High: ${severityCounts.high}, Medium: ${severityCounts.medium}, Low: ${severityCounts.low}, Info: ${severityCounts.info}`);
            }
          } else {
            console.log(`✅ Scan ${scanId} completed: No vulnerabilities found for ${data.target_url}`);
            console.log(`   - Standard Scanner, CWE Top 25 Scanner, and NIST SP 800-171 Scanner completed successfully`);
          }

          // Update scan status
          const { error: updateError } = await sb.from("scans").update({
            status: "completed",
            completed_at: new Date().toISOString(),
            severity_critical: severityCounts.critical,
            severity_high: severityCounts.high,
            severity_medium: severityCounts.medium,
            severity_low: severityCounts.low,
            severity_info: severityCounts.info,
            updated_at: new Date().toISOString()
          }).eq("id", scanId);

          if (updateError) {
            console.error("Error updating scan status to completed:", updateError);
          } else {
            console.log(`Scan ${scanId} status updated to completed successfully`);
          }

        } catch (error) {
          console.error("Scan failed:", error);
          await sb.from("scans").update({
            status: "failed",
            completed_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }).eq("id", scanId);
        }
      })()
    );

    return c.json(scan);
  } catch (error) {
    console.error("Unexpected error creating scan:", error);
    return c.json({
      error: "An unexpected error occurred while creating the scan",
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Trial scan endpoint - performs scan without storing data
app.post("/api/scans/trial", zValidator("json", CreateScanSchema), async (c) => {
  try {
    const data = c.req.valid("json");

    // Run all scanners in parallel (same as regular scan but don't save to DB)
    const [standardVulns, cweTop25Results, nistResults] = await Promise.all([
      // Standard Security Scanner
      (async () => {
        const scanner = new SecurityScanner({
          targetUrl: data.target_url,
          scanType: data.scan_type,
        });
        return await scanner.scan();
      })(),
      // CWE Top 25 Scanner
      (async () => {
        try {
          const cweScanner = new CWETop25Scanner({
            targetUrl: data.target_url,
          });
          return await cweScanner.scan();
        } catch (error) {
          console.warn("CWE Top 25 scanner failed:", error);
          return [];
        }
      })(),
      // NIST SP 800-171 Compliance Scanner
      (async () => {
        try {
          const nistScanner = new NISTSP800171Scanner({
            targetUrl: data.target_url,
          });
          return await nistScanner.scan();
        } catch (error) {
          console.warn("NIST SP 800-171 scanner failed:", error);
          return [];
        }
      })(),
    ]);

    // Convert CWE Top 25 results to VulnerabilityResult format
    const cweVulns = cweTop25Results
      .filter(result => result.detected)
      .map(result => ({
        title: `CWE Top 25 #${result.rank}: ${result.name} (${result.cwe_id})`,
        description: `${result.description}. Impact: ${result.impact}`,
        severity: result.severity,
        category: `CWE Top 25 - ${result.cwe_id}`,
        cvss_score: result.score,
        cwe_id: result.cwe_id,
        recommendation: result.recommendation,
        evidence: result.evidence || `CWE Top 25 vulnerability ${result.cwe_id} detected.`,
        scannerType: 'CWE',
      }));

    // Convert NIST SP 800-171 results to VulnerabilityResult format
    const nistVulns = nistResults
      .filter(result => !result.compliant)
      .map(result => ({
        title: `${result.title} (${result.control_id}) - Non-Compliant`,
        description: `${result.description}. Compliance: ${result.requirements_met}/${result.requirements_total} requirements met.`,
        severity: result.severity,
        category: `NIST SP 800-171 - ${result.category}`,
        cvss_score: result.severity === 'critical' ? 9.0 : result.severity === 'high' ? 7.0 : result.severity === 'medium' ? 5.0 : 3.0,
        cwe_id: null,
        recommendation: result.recommendation,
        evidence: result.evidence || `NIST control ${result.control_id} non-compliance detected. ${result.requirements_met}/${result.requirements_total} requirements met.`,
        scannerType: 'NIST',
      }));

    // Add scannerType to standard vulnerabilities
    const standardVulnsWithType = standardVulns.map(vuln => ({
      ...vuln,
      scannerType: 'STANDARD' as const,
    }));

    // Combine all scanner results
    const allVulnerabilities = [...standardVulnsWithType, ...cweVulns, ...nistVulns];

    // Count vulnerabilities by severity
    const severityCounts = {
      critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
      high: allVulnerabilities.filter(v => v.severity === 'high').length,
      medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
      low: allVulnerabilities.filter(v => v.severity === 'low').length,
      info: allVulnerabilities.filter(v => v.severity === 'info').length,
    };

    // Return trial scan results without saving to database
    return c.json({
      scan: {
        id: 'trial-' + Date.now(),
        target_url: data.target_url,
        scan_type: data.scan_type,
        status: 'completed',
        severity_critical: severityCounts.critical,
        severity_high: severityCounts.high,
        severity_medium: severityCounts.medium,
        severity_low: severityCounts.low,
        severity_info: severityCounts.info,
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      },
      vulnerabilities: allVulnerabilities.map((v, idx) => ({
        id: idx + 1,
        ...v,
      })),
    });
  } catch (error) {
    console.error("Trial scan error:", error);
    return c.json({
      error: "Failed to perform trial scan",
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Trial mobile scan endpoint - performs scan without storing data
app.post("/api/mobile-scans/trial", async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get("file") as File | null;
    const platform = formData.get("platform") as string;

    if (!file) return c.json({ error: "No file provided" }, 400);
    if (!platform || (platform !== "android" && platform !== "ios")) {
      return c.json({ error: "Invalid platform. Must be 'android' or 'ios'" }, 400);
    }

    // Validate file type
    const fileName = file.name.toLowerCase();
    const isValidAndroid = platform === "android" && fileName.endsWith(".apk");
    const isValidIOS = platform === "ios" && (fileName.endsWith(".ipa") || fileName.endsWith(".zip"));

    if (!isValidAndroid && !isValidIOS) {
      return c.json({
        error: `Invalid file type for ${platform}. Expected ${platform === "android" ? ".apk" : ".ipa or .zip"}`
      }, 400);
    }

    // Perform mobile scan without storing
    const fileBuffer = await file.arrayBuffer();
    const scanner = new MobileSecurityScanner({
      fileBuffer: fileBuffer,
      fileName: file.name,
      platform: platform as 'android' | 'ios',
    });

    const scanResult = await scanner.scan();
    const vulnerabilities = scanResult.vulnerabilities;

    // Count vulnerabilities by severity
    const severityCounts = {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      info: vulnerabilities.filter(v => v.severity === 'info').length,
    };

    // Return trial scan results without saving to database
    return c.json({
      scan: {
        id: 'trial-mobile-' + Date.now(),
        app_name: file.name,
        platform: platform,
        status: 'completed',
        severity_critical: severityCounts.critical,
        severity_high: severityCounts.high,
        severity_medium: severityCounts.medium,
        severity_low: severityCounts.low,
        severity_info: severityCounts.info,
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      },
      vulnerabilities: vulnerabilities.map((v, idx) => ({
        id: idx + 1,
        ...v,
      })),
    });
  } catch (error) {
    console.error("Trial mobile scan error:", error);
    return c.json({
      error: "Failed to perform trial mobile scan",
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Save trial web scan to database
app.post("/api/scans/save-trial", async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const body = await c.req.json();
    const { scan, vulnerabilities } = body;

    // Extract user_id from auth token
    let userId: string | null = null;
    const authHeader = c.req.header("Authorization");
    if (authHeader) {
      try {
        const token = authHeader.replace("Bearer ", "");
        const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
        const supabaseAnonKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

        if (supabaseUrl && supabaseAnonKey) {
          const userClient = createClient(supabaseUrl, supabaseAnonKey, {
            global: {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            },
          });
          const { data: { user }, error: userError } = await userClient.auth.getUser(token);
          if (!userError && user) {
            userId = user.id;
          }
        }
      } catch (err) {
        console.warn("Failed to extract user from token:", err);
      }
    }

    if (!userId) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Create scan record
    const insertData: any = {
      target_url: scan.target_url,
      scan_type: scan.scan_type || 'standard',
      status: 'completed',
      severity_critical: scan.severity_critical || 0,
      severity_high: scan.severity_high || 0,
      severity_medium: scan.severity_medium || 0,
      severity_low: scan.severity_low || 0,
      severity_info: scan.severity_info || 0,
      started_at: scan.started_at || new Date().toISOString(),
      completed_at: scan.completed_at || new Date().toISOString(),
      user_id: userId,
    };

    const { data: savedScan, error: scanError } = await supabase
      .from("scans")
      .insert(insertData)
      .select()
      .single();

    if (scanError || !savedScan) {
      console.error("Error saving trial scan:", scanError);
      return c.json({ error: "Failed to save scan" }, 500);
    }

    // Save vulnerabilities
    if (vulnerabilities && vulnerabilities.length > 0) {
      const vulnsToInsert = vulnerabilities.map((vuln: any) => ({
        scan_id: savedScan.id,
        title: sanitizeText(vuln.title) || "Unknown",
        description: sanitizeText(vuln.description) || "No description",
        severity: vuln.severity || "info",
        category: vuln.category || "Uncategorized",
        cvss_score: vuln.cvss_score || null,
        cwe_id: sanitizeText(vuln.cwe_id) || null,
        recommendation: sanitizeText(vuln.recommendation) || "No recommendation",
        evidence: sanitizeText(vuln.evidence) || null,
        user_id: userId,
      }));

      const { error: vulnError } = await supabase
        .from("web_vulnerabilities")
        .insert(vulnsToInsert);

      if (vulnError) {
        console.error("Error saving vulnerabilities:", vulnError);
        // Still return success for scan, vulnerabilities can be added later
      }
    }

    return c.json({ success: true, scan: savedScan });
  } catch (error) {
    console.error("Error saving trial scan:", error);
    return c.json({ error: "Failed to save trial scan" }, 500);
  }
});

// Save trial mobile scan to database
app.post("/api/mobile-scans/save-trial", async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const body = await c.req.json();
    const { scan, vulnerabilities } = body;

    // Extract user_id from auth token
    let userId: string | null = null;
    const authHeader = c.req.header("Authorization");
    if (authHeader) {
      try {
        const token = authHeader.replace("Bearer ", "");
        const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
        const supabaseAnonKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

        if (supabaseUrl && supabaseAnonKey) {
          const userClient = createClient(supabaseUrl, supabaseAnonKey, {
            global: {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            },
          });
          const { data: { user }, error: userError } = await userClient.auth.getUser(token);
          if (!userError && user) {
            userId = user.id;
          }
        }
      } catch (err) {
        console.warn("Failed to extract user from token:", err);
      }
    }

    if (!userId) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Create mobile scan record
    const insertData: any = {
      app_name: scan.app_name || "Unknown App",
      platform: scan.platform || "android",
      status: 'completed',
      severity_critical: scan.severity_critical || 0,
      severity_high: scan.severity_high || 0,
      severity_medium: scan.severity_medium || 0,
      severity_low: scan.severity_low || 0,
      severity_info: scan.severity_info || 0,
      started_at: scan.started_at || new Date().toISOString(),
      completed_at: scan.completed_at || new Date().toISOString(),
      user_id: userId,
      // Note: file_key and file_size won't be available for trial scans
      file_key: null,
      file_size: 0,
    };

    const { data: savedScan, error: scanError } = await supabase
      .from("mobile_scans")
      .insert(insertData)
      .select()
      .single();

    if (scanError || !savedScan) {
      console.error("Error saving trial mobile scan:", scanError);
      return c.json({ error: "Failed to save mobile scan" }, 500);
    }

    // Save vulnerabilities
    if (vulnerabilities && vulnerabilities.length > 0) {
      const vulnsToInsert = vulnerabilities.map((vuln: any) => ({
        mobile_scan_id: savedScan.id,
        title: sanitizeText(vuln.title) || "Unknown",
        description: sanitizeText(vuln.description) || "No description",
        severity: vuln.severity || "info",
        owasp_category: sanitizeText(vuln.owasp_category) || "Uncategorized",
        cvss_score: vuln.cvss_score || null,
        cwe_id: sanitizeText(vuln.cwe_id) || null,
        recommendation: sanitizeText(vuln.recommendation) || "No recommendation",
        evidence: sanitizeText(vuln.evidence) || null,
        file_path: sanitizeText(vuln.file_path) || null,
        code_snippet: sanitizeText(vuln.code_snippet) || null,
      }));

      const { error: vulnError } = await supabase
        .from("mobile_vulnerabilities")
        .insert(vulnsToInsert);

      if (vulnError) {
        console.error("Error saving mobile vulnerabilities:", vulnError);
      }
    }

    return c.json({ success: true, scan: savedScan });
  } catch (error) {
    console.error("Error saving trial mobile scan:", error);
    return c.json({ error: "Failed to save trial mobile scan" }, 500);
  }
});

// Delete a scan
app.delete("/api/scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");

  // With CASCADE delete on the DB table, deleting the scan automatically deletes vulns
  const { error } = await supabase.from("scans").delete().eq("id", id);

  if (error) return c.json({ error: error.message }, 500);
  return c.json({ success: true });
});

// Get dashboard statistics
app.get("/api/dashboard/stats", async (c) => {
  const supabase = getSupabase(c.env);
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { count: totalScans } = await supabase
    .from("scans")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);

  const { count: completedScans } = await supabase
    .from("scans")
    .select("*", { count: "exact", head: true })
    .eq("status", "completed")
    .eq("user_id", userId);

  const { count: runningScans } = await supabase
    .from("scans")
    .select("*", { count: "exact", head: true })
    .eq("status", "running")
    .eq("user_id", userId);

  const { count: totalVulnerabilities } = await supabase
    .from("web_vulnerabilities")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);

  const { count: criticalVulns } = await supabase
    .from("web_vulnerabilities")
    .select("*", { count: "exact", head: true })
    .eq("severity", "critical")
    .eq("user_id", userId);

  return c.json({
    totalScans: totalScans || 0,
    completedScans: completedScans || 0,
    runningScans: runningScans || 0,
    totalVulnerabilities: totalVulnerabilities || 0,
    criticalVulnerabilities: criticalVulns || 0,
  });
});

// CWE Top 25 Scanner endpoint
app.post("/api/scans/cwe-top-25", async (c) => {
  try {
    const body = await c.req.json();
    const targetUrl = body.target_url;

    if (!targetUrl) {
      return c.json({ error: "target_url is required" }, 400);
    }

    const scanner = new CWETop25Scanner({
      targetUrl: targetUrl,
    });

    const results = await scanner.scan();

    // Return results with rank, cwe_id, and other fields
    return c.json({
      success: true,
      target_url: targetUrl,
      total_checked: results.length,
      vulnerabilities_found: results.filter(v => v.detected).length,
      results: results.map(v => ({
        rank: v.rank,
        cwe_id: v.cwe_id,
        name: v.name,
        score: v.score,
        severity: v.severity,
        description: v.description,
        impact: v.impact,
        detected: v.detected,
        evidence: v.evidence,
        recommendation: v.recommendation,
        platforms: v.platforms,
      })),
    });
  } catch (error) {
    console.error("CWE Top 25 scan error:", error);
    return c.json({
      error: "Failed to perform CWE Top 25 scan",
      details: error instanceof Error ? error.message : "Unknown error"
    }, 500);
  }
});

// NIST SP 800-171 Compliance Scanner endpoint
app.post("/api/scans/nist-sp-800-171", async (c) => {
  try {
    const body = await c.req.json();
    const targetUrl = body.target_url;

    if (!targetUrl) {
      return c.json({ error: "target_url is required" }, 400);
    }

    const scanner = new NISTSP800171Scanner({
      targetUrl: targetUrl,
    });

    const results = await scanner.scan();

    // Return results with control_id, compliance status, and other fields
    return c.json({
      success: true,
      target_url: targetUrl,
      total_controls: results.length,
      compliant_controls: results.filter(v => v.compliant).length,
      non_compliant_controls: results.filter(v => !v.compliant).length,
      compliance_percentage: results.length > 0
        ? Math.round((results.filter(v => v.compliant).length / results.length) * 100)
        : 0,
      results: results.map(v => ({
        control_id: v.control_id,
        title: v.title,
        category: v.category,
        severity: v.severity,
        description: v.description,
        compliant: v.compliant,
        requirements_met: v.requirements_met,
        requirements_total: v.requirements_total,
        compliance_percentage: Math.round((v.requirements_met / v.requirements_total) * 100),
        evidence: v.evidence,
        recommendation: v.recommendation,
        nist_control: v.nist_control,
      })),
    });
  } catch (error) {
    console.error("NIST SP 800-171 scan error:", error);
    return c.json({
      error: "Failed to perform NIST SP 800-171 compliance scan",
      details: error instanceof Error ? error.message : "Unknown error"
    }, 500);
  }
});

// Export scan report
app.get("/api/scans/:id/export", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const format = c.req.query("format") || "pdf";

  const { data: scan } = await supabase.from("scans").select("*").eq("id", id).single();
  if (!scan) return c.json({ error: "Scan not found" }, 404);

  const { data: vulnerabilities } = await supabase.from("web_vulnerabilities").select("*").eq("scan_id", id);

  const reportData = {
    scan: scan as any,
    vulnerabilities: (vulnerabilities || []) as any[],
  };

  try {
    const { ReportGenerator } = await import("./report-generator");
    const generator = new ReportGenerator(reportData);

    switch (format) {
      case "pdf": {
        const pdfBuffer = generator.generatePDF();
        return c.body(pdfBuffer, 200, {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="cybersec-report-${id}.pdf"`,
        });
      }
      case "json": {
        const json = generator.generateJSON();
        return c.body(json, 200, {
          "Content-Type": "application/json",
          "Content-Disposition": `attachment; filename="cybersec-report-${id}.json"`,
        });
      }
      case "csv": {
        const csv = generator.generateCSV();
        return c.body(csv, 200, {
          "Content-Type": "text/csv",
          "Content-Disposition": `attachment; filename="cybersec-report-${id}.csv"`,
        });
      }
      case "html": {
        const html = generator.generateHTML();
        return c.body(html, 200, {
          "Content-Type": "text/html",
          "Content-Disposition": `attachment; filename="cybersec-report-${id}.html"`,
        });
      }
      default:
        return c.json({ error: "Invalid format" }, 400);
    }
  } catch (error) {
    console.error("Export error:", error);
    return c.json({ error: "Failed to generate report" }, 500);
  }
});

// Mobile scan endpoints

// Get all mobile scans
app.get("/api/mobile-scans", async (c) => {
  const supabase = getSupabase(c.env);
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { data, error } = await supabase
    .from("mobile_scans")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Get a single mobile scan
app.get("/api/mobile-scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { data, error } = await supabase
    .from("mobile_scans")
    .select("*")
    .eq("id", id)
    .eq("user_id", userId)
    .single();

  if (error || !data) return c.json({ error: "Mobile scan not found" }, 404);
  return c.json(data);
});

// Get vulnerabilities for a mobile scan
app.get("/api/mobile-scans/:id/vulnerabilities", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const userId = await getUserIdFromRequest(c);

  if (!userId) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Optional: ensure mobile scan belongs to user
  const { data: scan, error: scanError } = await supabase
    .from("mobile_scans")
    .select("id")
    .eq("id", id)
    .eq("user_id", userId)
    .maybeSingle();

  if (scanError || !scan) {
    return c.json({ error: "Mobile scan not found" }, 404);
  }

  const { data, error } = await supabase
    .from("mobile_vulnerabilities")
    .select("*")
    .eq("mobile_scan_id", id)
    .order("created_at", { ascending: false });

  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Create a new mobile scan with file upload
app.post("/api/mobile-scans", async (c) => {
  const supabase = getSupabase(c.env);
  const formData = await c.req.formData();

  const file = formData.get("file") as File | null;
  const platform = formData.get("platform") as string;

  if (!file) return c.json({ error: "No file provided" }, 400);

  if (!platform || (platform !== "android" && platform !== "ios")) {
    return c.json({ error: "Invalid platform. Must be 'android' or 'ios'" }, 400);
  }

  // Extract user_id from auth token
  let userId: string | null = null;
  const authHeader = c.req.header("Authorization");
  if (authHeader) {
    try {
      const token = authHeader.replace("Bearer ", "");
      const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
      const supabaseAnonKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);

      if (supabaseUrl && supabaseAnonKey) {
        const userClient = createClient(supabaseUrl, supabaseAnonKey, {
          global: {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          },
        });
        const { data: { user }, error: userError } = await userClient.auth.getUser(token);
        if (!userError && user) {
          userId = user.id;
        }
      }
    } catch (err) {
      console.warn("Failed to extract user from token:", err);
    }
  }

  // Validate file type
  const fileName = file.name.toLowerCase();
  const isValidAndroid = platform === "android" && fileName.endsWith(".apk");
  const isValidIOS = platform === "ios" && (fileName.endsWith(".ipa") || fileName.endsWith(".zip"));

  if (!isValidAndroid && !isValidIOS) {
    return c.json({
      error: `Invalid file type for ${platform}. Expected ${platform === "android" ? ".apk" : ".ipa or .zip"}`
    }, 400);
  }

  try {
    // Read file into memory for scanning (no persistent storage)
    if (file.size > MAX_UPLOAD_BYTES) {
      return c.json({ error: `File too large. Max allowed is ${MAX_UPLOAD_BYTES} bytes.` }, 400);
    }

    const fileBuffer = await file.arrayBuffer();
    const safeFileName = sanitizeFileName(file.name);

    // Create initial scan record — store sanitized filename in file_key (varchar)
    const insertData: any = {
      app_name: file.name,
      platform: platform,
      file_key: safeFileName, // store filename here as requested (no blob storage)
      file_size: file.size,
      status: "running",
      started_at: new Date().toISOString()
    };

    // Add user_id if available
    if (userId) {
      insertData.user_id = userId;
    }

    const { data: scan, error } = await supabase
      .from("mobile_scans")
      .insert(insertData)
      .select()
      .single();

    if (error || !scan) {
      console.error("DB Error:", error);
      return c.json({ error: "Failed to create mobile scan" }, 500);
    }

    const scanId = scan.id;

    // Run scan asynchronously (no R2)
    safeWaitUntil(c,
      (async () => {
        const supabaseUrl = c.env.SUPABASE_URL || (typeof process !== "undefined" ? process.env?.SUPABASE_URL : undefined);
        const supabaseKey = c.env.SUPABASE_KEY || (typeof process !== "undefined" ? process.env?.SUPABASE_KEY : undefined);
        if (!supabaseUrl || !supabaseKey) {
          console.error("Supabase credentials not available");
          return;
        }
        const sb = createClient(supabaseUrl, supabaseKey);
        try {
          const scanner = new MobileSecurityScanner({
            platform: platform as 'android' | 'ios',
            fileBuffer: fileBuffer,
            fileName: file.name,
          });

          const scanResult = await scanner.scan();

          // Update app metadata
          await sb.from("mobile_scans").update({
            app_name: scanResult.metadata.appName || file.name,
            package_name: scanResult.metadata.packageName,
            version: scanResult.metadata.version,
            updated_at: new Date().toISOString()
          }).eq("id", scanId);

          const severityCounts: Record<string, number> = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0,
          };

          // Insert vulnerabilities
          const vulnsToInsert = scanResult.vulnerabilities.map(vuln => {
            if (severityCounts[vuln.severity] !== undefined) {
              severityCounts[vuln.severity]++;
            }
            return {
              mobile_scan_id: scanId,
              title: sanitizeText(vuln.title) || "UNKNOWN",
              description: sanitizeText(vuln.description) || "No description provided",
              severity: vuln.severity,
              owasp_category: sanitizeText(vuln.owasp_category) || "Uncategorized",
              cvss_score: vuln.cvss_score || null,
              cwe_id: sanitizeText(vuln.cwe_id || null),
              recommendation: sanitizeText(vuln.recommendation),
              evidence: sanitizeText(vuln.evidence),
              file_path: sanitizeText(vuln.file_path),
              code_snippet: sanitizeText(vuln.code_snippet)
            };
          });

          if (vulnsToInsert.length > 0) {
            const { error: vulnError } = await sb.from("mobile_vulnerabilities").insert(vulnsToInsert);
            if (vulnError) {
              console.error("Error inserting mobile vulnerabilities:", vulnError);
            } else {
              console.log(`✅ Mobile Scan ${scanId} completed: Found ${vulnsToInsert.length} vulnerability/vulnerabilities`);
              console.log(`   - Critical: ${severityCounts.critical}, High: ${severityCounts.high}, Medium: ${severityCounts.medium}, Low: ${severityCounts.low}, Info: ${severityCounts.info}`);
            }
          } else {
            console.log(`✅ Mobile Scan ${scanId} completed: No vulnerabilities found for ${file.name} (${platform})`);
          }

          // Update scan status
          const { error: updateError } = await sb.from("mobile_scans").update({
            status: "completed",
            completed_at: new Date().toISOString(),
            severity_critical: severityCounts.critical,
            severity_high: severityCounts.high,
            severity_medium: severityCounts.medium,
            severity_low: severityCounts.low,
            severity_info: severityCounts.info,
            updated_at: new Date().toISOString()
          }).eq("id", scanId);

          if (updateError) {
            console.error("Error updating mobile scan status to completed:", updateError);
          } else {
            console.log(`Mobile Scan ${scanId} status updated to completed successfully`);
          }

        } catch (error) {
          console.error("Mobile scan failed:", error);
          await sb.from("mobile_scans").update({
            status: "failed",
            completed_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }).eq("id", scanId);
        }
      })()
    );

    return c.json(scan);
  } catch (error) {
    console.error("Error processing mobile scan:", error);
    return c.json({ error: "Failed to process file" }, 500);
  }
});

// Delete a mobile scan
app.delete("/api/mobile-scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");

  // Note: file_key now stores sanitized filename only, no persistent object to delete.
  // Simply remove DB row (CASCADE should clean vulnerabilities).
  const { error } = await supabase.from("mobile_scans").delete().eq("id", id);

  if (error) return c.json({ error: error.message }, 500);
  return c.json({ success: true });
});

// Export mobile scan report
app.get("/api/mobile-scans/:id/export", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const format = c.req.query("format") || "pdf";

  const { data: scan } = await supabase.from("mobile_scans").select("*").eq("id", id).single();
  if (!scan) return c.json({ error: "Mobile scan not found" }, 404);

  const { data: vulnerabilities } = await supabase.from("mobile_vulnerabilities").select("*").eq("mobile_scan_id", id);

  const reportData = {
    scan: scan as any,
    vulnerabilities: (vulnerabilities || []) as any[],
  };

  const { MobileReportGenerator } = await import("./mobile-report-generator");
  const generator = new MobileReportGenerator(reportData);

  try {
    switch (format) {
      case "pdf": {
        const pdfBuffer = generator.generatePDF();
        return c.body(pdfBuffer, 200, {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="mobile-security-report-${id}.pdf"`,
        });
      }
      case "json": {
        const json = generator.generateJSON();
        return c.body(json, 200, {
          "Content-Type": "application/json",
          "Content-Disposition": `attachment; filename="mobile-security-report-${id}.json"`,
        });
      }
      case "csv": {
        const csv = generator.generateCSV();
        return c.body(csv, 200, {
          "Content-Type": "text/csv",
          "Content-Disposition": `attachment; filename="mobile-security-report-${id}.csv"`,
        });
      }
      case "html": {
        const html = generator.generateHTML();
        return c.body(html, 200, {
          "Content-Type": "text/html",
          "Content-Disposition": `attachment; filename="mobile-security-report-${id}.html"`,
        });
      }
      default:
        return c.json({ error: "Invalid format" }, 400);
    }
  } catch (error) {
    console.error("Export error:", error);
    return c.json({ error: "Failed to generate report" }, 500);
  }
});

export default app;
