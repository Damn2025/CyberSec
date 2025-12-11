import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { cors } from "hono/cors";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { CreateScanSchema } from "@/shared/types";
import { SecurityScanner, CWETop25Scanner } from "./scanner";
import { ReportGenerator } from "./report-generator";
import { MobileSecurityScanner } from "./mobile-scanner";
import { MobileReportGenerator } from "./mobile-report-generator";
import * as wranglerConfig from "../../wrangler.json";

// Define the Env interface to include Supabase vars
type Env = {
  SUPABASE_URL?: string;
  SUPABASE_KEY?: string;
  R2_BUCKET?: R2Bucket;
};

const app = new Hono<{ Bindings: Env }>();

app.use("/*", cors());

// Helper to get Supabase client with fallback to wrangler.json
const getSupabase = (env: Env): SupabaseClient => {
  const supabaseUrl = env.SUPABASE_URL || wranglerConfig.vars?.SUPABASE_URL;
  const supabaseKey = env.SUPABASE_KEY || wranglerConfig.vars?.SUPABASE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    throw new Error("Supabase URL and Key must be configured. Check wrangler.json or environment variables.");
  }
  
  return createClient(supabaseUrl, supabaseKey);
};

// Get all scans
app.get("/api/scans", async (c) => {
  const supabase = getSupabase(c.env);
  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(50);
  // console.log("data", data);
  // console.log("error", error);
  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Get a single scan
app.get("/api/scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  
  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .eq("id", id)
    .single();
  
  if (error || !data) return c.json({ error: "Scan not found" }, 404);
  return c.json(data);
});

// Get vulnerabilities for a scan
app.get("/api/scans/:id/vulnerabilities", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  
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
        
        const result = await supabase
          .from("scans")
          .insert({
            target_url: data.target_url,
            scan_type: data.scan_type,
            status: "running",
            started_at: new Date().toISOString()
          })
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
    c.executionCtx.waitUntil(
      (async () => {
        // Re-initialize supabase inside async context to be safe
        const supabaseUrl = c.env.SUPABASE_URL || wranglerConfig.vars?.SUPABASE_URL;
        const supabaseKey = c.env.SUPABASE_KEY || wranglerConfig.vars?.SUPABASE_KEY;
        if (!supabaseUrl || !supabaseKey) {
          console.error("Supabase credentials not available");
          return;
        }
        const sb = createClient(supabaseUrl, supabaseKey);
        
        try {
          // Run both scanners in parallel
          const [standardVulns, cweTop25Results] = await Promise.all([
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
              evidence: result.evidence || `CWE Top 25 vulnerability detected. Impact: ${result.impact}. Platforms: ${result.platforms.join(', ')}.`
            }));

          // Combine both scanner results
          const allVulnerabilities = [...standardVulns, ...cweVulns];
          
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
          
          const severityCounts: Record<string, number> = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0,
          };
          
          // Batch insert vulnerabilities
          const vulnsToInsert = vulnerabilities.map(vuln => {
            if (severityCounts[vuln.severity] !== undefined) {
              severityCounts[vuln.severity]++;
            }
            return {
              scan_id: scanId,
              title: vuln.title,
              description: vuln.description,
              severity: vuln.severity,
              category: vuln.category,
              cvss_score: vuln.cvss_score || null,
              cwe_id: vuln.cwe_id || null,
              recommendation: vuln.recommendation,
              evidence: vuln.evidence || null
            };
          });

          if (vulnsToInsert.length > 0) {
              const { error: vulnError } = await sb.from("web_vulnerabilities").insert(vulnsToInsert);
              if (vulnError) {
                console.error("Error inserting vulns:", vulnError);
              } else {
                const standardCount = standardVulns.length;
                const cweCount = cweVulns.length;
                console.log(`✅ Scan ${scanId} completed: Found ${vulnsToInsert.length} unique vulnerability/vulnerabilities`);
                console.log(`   - Standard Scanner: ${standardCount} vulnerabilities`);
                console.log(`   - CWE Top 25 Scanner: ${cweCount} vulnerabilities detected`);
                console.log(`   - Severity Breakdown: Critical: ${severityCounts.critical}, High: ${severityCounts.high}, Medium: ${severityCounts.medium}, Low: ${severityCounts.low}, Info: ${severityCounts.info}`);
              }
          } else {
            console.log(`✅ Scan ${scanId} completed: No vulnerabilities found for ${data.target_url}`);
            console.log(`   - Both Standard Scanner and CWE Top 25 Scanner completed successfully`);
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
  
  const { count: totalScans } = await supabase.from("scans").select("*", { count: "exact", head: true });
  const { count: completedScans } = await supabase.from("scans").select("*", { count: "exact", head: true }).eq("status", "completed");
  const { count: runningScans } = await supabase.from("scans").select("*", { count: "exact", head: true }).eq("status", "running");
  const { count: totalVulnerabilities } = await supabase.from("web_vulnerabilities").select("*", { count: "exact", head: true });
  const { count: criticalVulns } = await supabase.from("web_vulnerabilities").select("*", { count: "exact", head: true }).eq("severity", "critical");
  
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
  
  const generator = new ReportGenerator(reportData);
  
  try {
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
  const { data, error } = await supabase
    .from("mobile_scans")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(50);
    
  if (error) return c.json({ error: error.message }, 500);
  return c.json(data);
});

// Get a single mobile scan
app.get("/api/mobile-scans/:id", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
  const { data, error } = await supabase
    .from("mobile_scans")
    .select("*")
    .eq("id", id)
    .single();
  
  if (error || !data) return c.json({ error: "Mobile scan not found" }, 404);
  return c.json(data);
});

// Get vulnerabilities for a mobile scan
app.get("/api/mobile-scans/:id/vulnerabilities", async (c) => {
  const supabase = getSupabase(c.env);
  const id = c.req.param("id");
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
    // Store file in R2
    const fileBuffer = await file.arrayBuffer();
    const fileKey = `mobile-apps/${Date.now()}-${file.name}`;
    
    if (!c.env.R2_BUCKET) {
      return c.json({ error: "R2 bucket not configured" }, 500);
    }
    
    await c.env.R2_BUCKET.put(fileKey, fileBuffer, {
      httpMetadata: {
        contentType: file.type || "application/octet-stream",
      },
      customMetadata: {
        originalName: file.name,
        platform: platform,
      },
    });
    
    // Create initial scan record
    const { data: scan, error } = await supabase
      .from("mobile_scans")
      .insert({
        app_name: file.name,
        platform: platform,
        file_key: fileKey,
        file_size: file.size,
        status: "running",
        started_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error || !scan) {
      console.error("DB Error:", error);
      return c.json({ error: "Failed to create mobile scan" }, 500);
    }
    
    const scanId = scan.id;
    
    // Run scan asynchronously
    c.executionCtx.waitUntil(
      (async () => {
        const supabaseUrl = c.env.SUPABASE_URL || wranglerConfig.vars?.SUPABASE_URL;
        const supabaseKey = c.env.SUPABASE_KEY || wranglerConfig.vars?.SUPABASE_KEY;
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
              title: vuln.title,
              description: vuln.description,
              severity: vuln.severity,
              owasp_category: vuln.owasp_category,
              cvss_score: vuln.cvss_score || null,
              cwe_id: vuln.cwe_id || null,
              recommendation: vuln.recommendation,
              evidence: vuln.evidence || null,
              file_path: vuln.file_path || null,
              code_snippet: vuln.code_snippet || null
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
  
  // Get scan to find file key
  const { data: scan } = await supabase
    .from("mobile_scans")
    .select("file_key")
    .eq("id", id)
    .single();
  
  if (scan?.file_key && c.env.R2_BUCKET) {
    try {
      await c.env.R2_BUCKET.delete(scan.file_key);
    } catch (error) {
      console.error("Error deleting file from R2:", error);
    }
  }
  
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
