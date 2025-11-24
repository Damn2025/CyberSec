import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { cors } from "hono/cors";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { CreateScanSchema } from "@/shared/types";
import { SecurityScanner } from "./scanner";
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
  const supabase = getSupabase(c.env);
  const data = c.req.valid("json");
  
  // Create scan record
  const { data: scan, error } = await supabase
    .from("scans")
    .insert({
      target_url: data.target_url,
      scan_type: data.scan_type,
      status: "running",
      started_at: new Date().toISOString()
    })
    .select()
    .single();
  
  if (error || !scan) {
    console.error("Create scan error:", error);
    return c.json({ error: "Failed to create scan" }, 500);
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
        const scanner = new SecurityScanner({
          targetUrl: data.target_url,
          scanType: data.scan_type,
        });
        
        const vulnerabilities = await scanner.scan();
        console.log("vulnerabilities", vulnerabilities);
        
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
            if (vulnError) console.error("Error inserting vulns:", vulnError);
        }
        
        // Update scan status
        await sb.from("scans").update({
           status: "completed",
           completed_at: new Date().toISOString(),
           severity_critical: severityCounts.critical,
           severity_high: severityCounts.high,
           severity_medium: severityCounts.medium,
           severity_low: severityCounts.low,
           severity_info: severityCounts.info,
           updated_at: new Date().toISOString()
        }).eq("id", scanId);

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
  const { count: criticalVulns } = await supabase.from("vulnerabilities").select("*", { count: "exact", head: true }).eq("severity", "critical");
  
  return c.json({
    totalScans: totalScans || 0,
    completedScans: completedScans || 0,
    runningScans: runningScans || 0,
    totalVulnerabilities: totalVulnerabilities || 0,
    criticalVulnerabilities: criticalVulns || 0,
  });
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
             await sb.from("mobile_vulnerabilities").insert(vulnsToInsert);
          }
          
          // Update scan status
          await sb.from("mobile_scans").update({
             status: "completed",
             completed_at: new Date().toISOString(),
             severity_critical: severityCounts.critical,
             severity_high: severityCounts.high,
             severity_medium: severityCounts.medium,
             severity_low: severityCounts.low,
             severity_info: severityCounts.info,
             updated_at: new Date().toISOString()
          }).eq("id", scanId);

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
