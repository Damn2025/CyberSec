import z from "zod";

export const ScanTypeSchema = z.enum([
  "quick",
  "standard",
  "comprehensive",
  "api",
  "mobile"
]);

export const SeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info"
]);

export const ScanStatusSchema = z.enum([
  "pending",
  "running",
  "completed",
  "failed"
]);

export const CreateScanSchema = z.object({
  target_url: z.string().url(),
  scan_type: ScanTypeSchema,
});

export const ScanSchema = z.object({
  id: z.number(),
  target_url: z.string(),
  scan_type: z.string(),
  status: z.string(),
  severity_critical: z.number(),
  severity_high: z.number(),
  severity_medium: z.number(),
  severity_low: z.number(),
  severity_info: z.number(),
  started_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const VulnerabilitySchema = z.object({
  id: z.number(),
  scan_id: z.number(),
  title: z.string(),
  description: z.string(),
  severity: z.string(),
  category: z.string(),
  cvss_score: z.number().nullable(),
  cwe_id: z.string().nullable(),
  recommendation: z.string().nullable(),
  evidence: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type ScanType = z.infer<typeof ScanTypeSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type ScanStatus = z.infer<typeof ScanStatusSchema>;
export type CreateScan = z.infer<typeof CreateScanSchema>;
export type Scan = z.infer<typeof ScanSchema>;
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

// Mobile scan types
export const MobilePlatformSchema = z.enum(["android", "ios"]);

export const MobileScanSchema = z.object({
  id: z.number(),
  app_name: z.string(),
  package_name: z.string().nullable(),
  version: z.string().nullable(),
  platform: z.string(),
  file_key: z.string(),
  file_size: z.number(),
  status: z.string(),
  severity_critical: z.number(),
  severity_high: z.number(),
  severity_medium: z.number(),
  severity_low: z.number(),
  severity_info: z.number(),
  started_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const MobileVulnerabilitySchema = z.object({
  id: z.number(),
  mobile_scan_id: z.number(),
  title: z.string(),
  description: z.string(),
  severity: z.string(),
  owasp_category: z.string(),
  cvss_score: z.number().nullable(),
  cwe_id: z.string().nullable(),
  recommendation: z.string().nullable(),
  evidence: z.string().nullable(),
  file_path: z.string().nullable(),
  code_snippet: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type MobilePlatform = z.infer<typeof MobilePlatformSchema>;
export type MobileScan = z.infer<typeof MobileScanSchema>;
export type MobileVulnerability = z.infer<typeof MobileVulnerabilitySchema>;
