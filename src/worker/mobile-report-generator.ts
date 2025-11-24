import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface MobileReportData {
  scan: {
    id: number;
    app_name: string;
    package_name: string | null;
    version: string | null;
    platform: string;
    status: string;
    severity_critical: number;
    severity_high: number;
    severity_medium: number;
    severity_low: number;
    severity_info: number;
    started_at: string | null;
    completed_at: string | null;
  };
  vulnerabilities: Array<{
    id: number;
    title: string;
    description: string;
    severity: string;
    owasp_category: string;
    cvss_score: number | null;
    cwe_id: string | null;
    recommendation: string | null;
    evidence: string | null;
    file_path: string | null;
    code_snippet: string | null;
  }>;
}

export class MobileReportGenerator {
  private data: MobileReportData;

  constructor(data: MobileReportData) {
    this.data = data;
  }

  generatePDF(): ArrayBuffer {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    
    // Title
    doc.setFontSize(24);
    doc.setTextColor(59, 130, 246);
    doc.text('CyberSec Mobile Security Report', 14, 20);
    
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 27);
    
    // App Information
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Application Information', 14, 40);
    
    doc.setFontSize(10);
    doc.setTextColor(60, 60, 60);
    doc.text(`App Name: ${this.data.scan.app_name}`, 14, 48);
    doc.text(`Platform: ${this.data.scan.platform.toUpperCase()}`, 14, 54);
    if (this.data.scan.package_name) {
      doc.text(`Package: ${this.data.scan.package_name}`, 14, 60);
    }
    if (this.data.scan.version) {
      doc.text(`Version: ${this.data.scan.version}`, 14, 66);
    }
    doc.text(`Status: ${this.data.scan.status}`, 14, 72);
    
    if (this.data.scan.completed_at) {
      doc.text(`Completed: ${new Date(this.data.scan.completed_at).toLocaleString()}`, 14, 78);
    }
    
    // Executive Summary
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Executive Summary', 14, 91);
    
    const critical = this.data.scan.severity_critical;
    const high = this.data.scan.severity_high;
    const medium = this.data.scan.severity_medium;
    const low = this.data.scan.severity_low;
    const info = this.data.scan.severity_info;
    
    // Summary table
    autoTable(doc, {
      startY: 96,
      head: [['Severity', 'Count', 'Risk Level']],
      body: [
        ['Critical', critical.toString(), 'CRITICAL - Immediate action required'],
        ['High', high.toString(), 'HIGH - Address urgently'],
        ['Medium', medium.toString(), 'MEDIUM - Address soon'],
        ['Low', low.toString(), 'LOW - Address when possible'],
        ['Info', info.toString(), 'INFO - For awareness'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [59, 130, 246], textColor: 255 },
      styles: { fontSize: 9 },
      columnStyles: {
        0: { cellWidth: 30 },
        1: { cellWidth: 20, halign: 'center' },
        2: { cellWidth: 'auto' },
      },
    });
    
    // OWASP Mobile Top 10 Categories
    doc.addPage();
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('OWASP Mobile Top 10 Findings', 14, 20);
    
    const owaspCategories = new Map<string, number>();
    this.data.vulnerabilities.forEach(v => {
      const count = owaspCategories.get(v.owasp_category) || 0;
      owaspCategories.set(v.owasp_category, count + 1);
    });
    
    if (owaspCategories.size > 0) {
      const owaspData = Array.from(owaspCategories.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([category, count]) => [category, count.toString()]);
      
      autoTable(doc, {
        startY: 25,
        head: [['OWASP Category', 'Issues Found']],
        body: owaspData,
        theme: 'grid',
        headStyles: { fillColor: [139, 92, 246], textColor: 255 },
        styles: { fontSize: 9 },
      });
    }
    
    // Vulnerability Details
    doc.addPage();
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('Vulnerability Details', 14, 20);
    
    let yPos = 30;
    
    this.data.vulnerabilities.forEach((vuln, index) => {
      if (yPos > 250) {
        doc.addPage();
        yPos = 20;
      }
      
      // Vulnerability title with number
      doc.setFontSize(12);
      doc.setTextColor(0, 0, 0);
      doc.text(`${index + 1}. ${vuln.title}`, 14, yPos);
      yPos += 7;
      
      // Severity and OWASP category
      doc.setFontSize(9);
      const severityColors: Record<string, [number, number, number]> = {
        critical: [239, 68, 68],
        high: [249, 115, 22],
        medium: [234, 179, 8],
        low: [59, 130, 246],
        info: [107, 114, 128],
      };
      const color = severityColors[vuln.severity] || [107, 114, 128];
      doc.setTextColor(color[0], color[1], color[2]);
      doc.text(`Severity: ${vuln.severity.toUpperCase()}`, 14, yPos);
      yPos += 5;
      
      doc.setTextColor(60, 60, 60);
      doc.text(`OWASP: ${vuln.owasp_category}`, 14, yPos);
      
      if (vuln.cvss_score) {
        doc.text(`CVSS: ${vuln.cvss_score.toFixed(1)}`, 100, yPos);
      }
      if (vuln.cwe_id) {
        doc.text(`${vuln.cwe_id}`, 140, yPos);
      }
      yPos += 7;
      
      // Description
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      const descLines = doc.splitTextToSize(vuln.description, pageWidth - 28);
      doc.text(descLines, 14, yPos);
      yPos += descLines.length * 5 + 3;
      
      // File path
      if (vuln.file_path) {
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text(`File: ${vuln.file_path}`, 14, yPos);
        yPos += 4;
      }
      
      // Recommendation
      if (vuln.recommendation) {
        doc.setFontSize(9);
        doc.setTextColor(22, 163, 74);
        doc.text('Recommendation:', 14, yPos);
        yPos += 5;
        
        doc.setTextColor(60, 60, 60);
        const recLines = doc.splitTextToSize(vuln.recommendation, pageWidth - 28);
        doc.text(recLines, 14, yPos);
        yPos += recLines.length * 5 + 3;
      }
      
      // Evidence
      if (vuln.evidence) {
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text('Evidence:', 14, yPos);
        yPos += 4;
        
        const evidenceLines = doc.splitTextToSize(vuln.evidence, pageWidth - 28);
        doc.text(evidenceLines, 14, yPos);
        yPos += evidenceLines.length * 4 + 3;
      }
      
      // Code snippet
      if (vuln.code_snippet) {
        doc.setFontSize(7);
        doc.setTextColor(80, 80, 80);
        doc.text('Code:', 14, yPos);
        yPos += 3;
        
        const codeLines = doc.splitTextToSize(vuln.code_snippet, pageWidth - 28);
        doc.text(codeLines, 14, yPos);
        yPos += codeLines.length * 3 + 3;
      }
      
      yPos += 5;
    });
    
    // Footer on all pages
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(
        `CyberSec Mobile Security Report - Page ${i} of ${totalPages}`,
        pageWidth / 2,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'center' }
      );
    }
    
    return doc.output('arraybuffer');
  }

  generateJSON(): string {
    return JSON.stringify({
      report_metadata: {
        generated_at: new Date().toISOString(),
        scanner: 'CyberSec Mobile Scanner',
        version: '1.0',
        scan_type: 'Mobile Application Security',
      },
      application: {
        name: this.data.scan.app_name,
        package_name: this.data.scan.package_name,
        version: this.data.scan.version,
        platform: this.data.scan.platform,
      },
      scan: this.data.scan,
      vulnerabilities: this.data.vulnerabilities,
      summary: {
        total_vulnerabilities: this.data.vulnerabilities.length,
        by_severity: {
          critical: this.data.scan.severity_critical,
          high: this.data.scan.severity_high,
          medium: this.data.scan.severity_medium,
          low: this.data.scan.severity_low,
          info: this.data.scan.severity_info,
        },
        owasp_categories: this.getOwaspCategorySummary(),
      },
    }, null, 2);
  }

  generateCSV(): string {
    const headers = [
      'ID',
      'Title',
      'Severity',
      'OWASP Category',
      'CVSS Score',
      'CWE ID',
      'Description',
      'Recommendation',
      'Evidence',
      'File Path',
    ];
    
    const rows = this.data.vulnerabilities.map(v => [
      v.id.toString(),
      `"${v.title.replace(/"/g, '""')}"`,
      v.severity,
      `"${v.owasp_category.replace(/"/g, '""')}"`,
      v.cvss_score?.toString() || '',
      v.cwe_id || '',
      `"${v.description.replace(/"/g, '""')}"`,
      `"${(v.recommendation || '').replace(/"/g, '""')}"`,
      `"${(v.evidence || '').replace(/"/g, '""')}"`,
      `"${(v.file_path || '').replace(/"/g, '""')}"`,
    ]);
    
    return [
      headers.join(','),
      ...rows.map(row => row.join(',')),
    ].join('\n');
  }

  generateHTML(): string {
    const totalVulns = this.data.vulnerabilities.length;
    
    const severityColors: Record<string, string> = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6',
      info: '#6b7280',
    };
    
    const owaspSummary = this.getOwaspCategorySummary();
    const owaspHTML = Object.entries(owaspSummary)
      .sort((a, b) => b[1] - a[1])
      .map(([category, count]) => `
        <div style="background: #f9fafb; padding: 15px; border-radius: 8px; border-left: 3px solid #8b5cf6;">
          <div style="font-weight: 600; color: #111827; margin-bottom: 4px;">${category}</div>
          <div style="color: #6b7280; font-size: 14px;">${count} issue${count !== 1 ? 's' : ''} found</div>
        </div>
      `)
      .join('');
    
    const vulnerabilitiesHTML = this.data.vulnerabilities
      .map((vuln, index) => {
        const color = severityColors[vuln.severity] || '#6b7280';
        return `
          <div class="vulnerability" style="margin-bottom: 30px; padding: 20px; background: #f9fafb; border-left: 4px solid ${color}; border-radius: 8px;">
            <h3 style="margin: 0 0 10px 0; color: #111827;">${index + 1}. ${vuln.title}</h3>
            <div style="margin-bottom: 15px;">
              <span class="badge" style="display: inline-block; padding: 4px 12px; background: ${color}; color: white; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; margin-right: 8px;">
                ${vuln.severity}
              </span>
              <span style="color: #6b7280; font-size: 14px; margin-right: 12px;">OWASP: ${vuln.owasp_category}</span>
              ${vuln.cvss_score ? `<span style="color: #6b7280; font-size: 14px; margin-right: 12px;">CVSS: ${vuln.cvss_score.toFixed(1)}</span>` : ''}
              ${vuln.cwe_id ? `<span style="color: #6b7280; font-size: 14px;">${vuln.cwe_id}</span>` : ''}
            </div>
            <p style="color: #4b5563; line-height: 1.6; margin-bottom: 15px;">${vuln.description}</p>
            ${vuln.file_path ? `
              <div style="background: #fef3c7; padding: 10px; border-radius: 6px; margin-bottom: 10px; font-size: 13px; color: #92400e;">
                📄 <strong>File:</strong> ${vuln.file_path}
              </div>
            ` : ''}
            ${vuln.recommendation ? `
              <div style="background: #ecfdf5; padding: 15px; border-radius: 6px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 8px 0; color: #059669; font-size: 14px;">💡 Recommendation</h4>
                <p style="margin: 0; color: #047857; line-height: 1.6;">${vuln.recommendation}</p>
              </div>
            ` : ''}
            ${vuln.evidence ? `
              <div style="background: #f3f4f6; padding: 12px; border-radius: 6px; font-size: 12px; color: #374151; margin-bottom: 10px;">
                <strong>Evidence:</strong><br>
                ${vuln.evidence.replace(/\n/g, '<br>')}
              </div>
            ` : ''}
            ${vuln.code_snippet ? `
              <div style="background: #1f2937; padding: 12px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 11px; color: #d1d5db; overflow-x: auto;">
                <strong style="color: #9ca3af;">Code Snippet:</strong><br>
                <pre style="margin: 8px 0 0 0; white-space: pre-wrap;">${vuln.code_snippet.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
              </div>
            ` : ''}
          </div>
        `;
      })
      .join('');

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberSec Mobile Security Report - ${this.data.scan.app_name}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #1f2937;
      background: #ffffff;
      padding: 40px 20px;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    .header {
      background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
      color: white;
      padding: 40px;
      border-radius: 12px;
      margin-bottom: 40px;
      box-shadow: 0 10px 40px rgba(139, 92, 246, 0.3);
    }
    .header h1 { font-size: 36px; margin-bottom: 10px; }
    .header p { opacity: 0.9; font-size: 14px; }
    .app-info {
      background: #f9fafb;
      padding: 25px;
      border-radius: 12px;
      margin-bottom: 40px;
      border: 1px solid #e5e7eb;
    }
    .app-info h2 { color: #111827; margin-bottom: 15px; font-size: 20px; }
    .app-info p { color: #6b7280; margin-bottom: 8px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }
    .summary-card {
      background: white;
      padding: 20px;
      border-radius: 12px;
      text-align: center;
      border: 2px solid #e5e7eb;
      transition: transform 0.2s;
    }
    .summary-card:hover { transform: translateY(-2px); }
    .summary-card .count {
      font-size: 36px;
      font-weight: bold;
      margin-bottom: 8px;
    }
    .summary-card .label {
      color: #6b7280;
      text-transform: uppercase;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    .critical { color: #ef4444; border-color: #ef4444; }
    .high { color: #f97316; border-color: #f97316; }
    .medium { color: #eab308; border-color: #eab308; }
    .low { color: #3b82f6; border-color: #3b82f6; }
    .info { color: #6b7280; border-color: #6b7280; }
    .owasp-section {
      background: #f9fafb;
      padding: 30px;
      border-radius: 12px;
      margin-bottom: 40px;
      border: 1px solid #e5e7eb;
    }
    .owasp-section h2 {
      color: #111827;
      margin-bottom: 20px;
      font-size: 24px;
    }
    .owasp-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 15px;
    }
    .vulnerabilities h2 {
      color: #111827;
      margin-bottom: 25px;
      font-size: 24px;
      padding-bottom: 15px;
      border-bottom: 2px solid #e5e7eb;
    }
    .footer {
      margin-top: 60px;
      padding-top: 30px;
      border-top: 2px solid #e5e7eb;
      text-align: center;
      color: #9ca3af;
      font-size: 14px;
    }
    @media print {
      body { padding: 20px; }
      .summary { page-break-inside: avoid; }
      .vulnerability { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>📱 CyberSec Mobile Security Report</h1>
      <p>Generated: ${new Date().toLocaleString()}</p>
    </div>

    <div class="app-info">
      <h2>Application Information</h2>
      <p><strong>App Name:</strong> ${this.data.scan.app_name}</p>
      <p><strong>Platform:</strong> ${this.data.scan.platform.toUpperCase()}</p>
      ${this.data.scan.package_name ? `<p><strong>Package:</strong> ${this.data.scan.package_name}</p>` : ''}
      ${this.data.scan.version ? `<p><strong>Version:</strong> ${this.data.scan.version}</p>` : ''}
      <p><strong>Status:</strong> ${this.data.scan.status}</p>
      ${this.data.scan.completed_at ? `<p><strong>Completed:</strong> ${new Date(this.data.scan.completed_at).toLocaleString()}</p>` : ''}
    </div>

    <div class="summary">
      <div class="summary-card critical">
        <div class="count">${this.data.scan.severity_critical}</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="count">${this.data.scan.severity_high}</div>
        <div class="label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="count">${this.data.scan.severity_medium}</div>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="count">${this.data.scan.severity_low}</div>
        <div class="label">Low</div>
      </div>
      <div class="summary-card info">
        <div class="count">${this.data.scan.severity_info}</div>
        <div class="label">Info</div>
      </div>
    </div>

    <div class="owasp-section">
      <h2>OWASP Mobile Top 10 Findings</h2>
      <div class="owasp-grid">
        ${owaspHTML}
      </div>
    </div>

    <div class="vulnerabilities">
      <h2>Vulnerability Details (${totalVulns} found)</h2>
      ${vulnerabilitiesHTML}
    </div>

    <div class="footer">
      <p>This report was generated by CyberSec - Mobile Application Security Scanner</p>
      <p>Based on OWASP Mobile Top 10 security standards</p>
    </div>
  </div>
</body>
</html>
    `.trim();
  }

  private getOwaspCategorySummary(): Record<string, number> {
    const summary: Record<string, number> = {};
    this.data.vulnerabilities.forEach(v => {
      summary[v.owasp_category] = (summary[v.owasp_category] || 0) + 1;
    });
    return summary;
  }
}
