import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface ReportData {
  scan: {
    id: number;
    target_url: string;
    scan_type: string;
    status: string;
    started_at: string | null;
    completed_at: string | null;
    severity_critical: number;
    severity_high: number;
    severity_medium: number;
    severity_low: number;
    severity_info: number;
  };
  vulnerabilities: Array<{
    id: number;
    title: string;
    description: string;
    severity: string;
    category: string;
    cvss_score: number | null;
    cwe_id: string | null;
    recommendation: string | null;
    evidence: string | null;
  }>;
}

export class ReportGenerator {
  private data: ReportData;

  constructor(data: ReportData) {
    this.data = data;
  }

  generatePDF(): ArrayBuffer {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    
    // Title
    doc.setFontSize(24);
    doc.setTextColor(59, 130, 246);
    doc.text('CyberSec Security Report', 14, 20);
    
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 27);
    
    // Scan Information
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Scan Information', 14, 40);
    
    doc.setFontSize(10);
    doc.setTextColor(60, 60, 60);
    doc.text(`Target URL: ${this.data.scan.target_url}`, 14, 48);
    doc.text(`Scan Type: ${this.data.scan.scan_type}`, 14, 54);
    doc.text(`Status: ${this.data.scan.status}`, 14, 60);
    doc.text(`Scan ID: ${this.data.scan.id}`, 14, 66);
    
    if (this.data.scan.completed_at) {
      doc.text(`Completed: ${new Date(this.data.scan.completed_at).toLocaleString()}`, 14, 72);
    }
    
    // Executive Summary
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Executive Summary', 14, 85);
    
    const critical = this.data.scan.severity_critical;
    const high = this.data.scan.severity_high;
    const medium = this.data.scan.severity_medium;
    const low = this.data.scan.severity_low;
    const info = this.data.scan.severity_info;
    
    // Summary table
    autoTable(doc, {
      startY: 90,
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
      
      // Severity badge
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
      
      doc.setTextColor(60, 60, 60);
      doc.text(`Category: ${vuln.category}`, 70, yPos);
      
      if (vuln.cvss_score) {
        doc.text(`CVSS: ${vuln.cvss_score.toFixed(1)}`, 130, yPos);
      }
      if (vuln.cwe_id) {
        doc.text(`${vuln.cwe_id}`, 160, yPos);
      }
      yPos += 7;
      
      // Description
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      const descLines = doc.splitTextToSize(vuln.description, pageWidth - 28);
      doc.text(descLines, 14, yPos);
      yPos += descLines.length * 5 + 3;
      
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
        yPos += evidenceLines.length * 4 + 5;
      }
      
      yPos += 5;
    });
    
    // Footer on last page
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(
        `CyberSec Report - Page ${i} of ${totalPages}`,
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
        scanner: 'CyberSec',
        version: '1.0',
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
      },
    }, null, 2);
  }

  generateCSV(): string {
    const headers = [
      'ID',
      'Title',
      'Severity',
      'Category',
      'CVSS Score',
      'CWE ID',
      'Description',
      'Recommendation',
      'Evidence'
    ];
    
    const rows = this.data.vulnerabilities.map(v => [
      v.id.toString(),
      `"${v.title.replace(/"/g, '""')}"`,
      v.severity,
      v.category,
      v.cvss_score?.toString() || '',
      v.cwe_id || '',
      `"${v.description.replace(/"/g, '""')}"`,
      `"${(v.recommendation || '').replace(/"/g, '""')}"`,
      `"${(v.evidence || '').replace(/"/g, '""')}"`,
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
              <span style="color: #6b7280; font-size: 14px; margin-right: 12px;">Category: ${vuln.category}</span>
              ${vuln.cvss_score ? `<span style="color: #6b7280; font-size: 14px; margin-right: 12px;">CVSS: ${vuln.cvss_score.toFixed(1)}</span>` : ''}
              ${vuln.cwe_id ? `<span style="color: #6b7280; font-size: 14px;">${vuln.cwe_id}</span>` : ''}
            </div>
            <p style="color: #4b5563; line-height: 1.6; margin-bottom: 15px;">${vuln.description}</p>
            ${vuln.recommendation ? `
              <div style="background: #ecfdf5; padding: 15px; border-radius: 6px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 8px 0; color: #059669; font-size: 14px;">💡 Recommendation</h4>
                <p style="margin: 0; color: #047857; line-height: 1.6;">${vuln.recommendation}</p>
              </div>
            ` : ''}
            ${vuln.evidence ? `
              <div style="background: #f3f4f6; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #374151; overflow-x: auto;">
                <strong>Evidence:</strong><br>
                ${vuln.evidence.replace(/\n/g, '<br>')}
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
  <title>CyberSec Security Report - ${this.data.scan.target_url}</title>
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
      background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
      color: white;
      padding: 40px;
      border-radius: 12px;
      margin-bottom: 40px;
      box-shadow: 0 10px 40px rgba(59, 130, 246, 0.3);
    }
    .header h1 { font-size: 36px; margin-bottom: 10px; }
    .header p { opacity: 0.9; font-size: 14px; }
    .scan-info {
      background: #f9fafb;
      padding: 25px;
      border-radius: 12px;
      margin-bottom: 40px;
      border: 1px solid #e5e7eb;
    }
    .scan-info h2 { color: #111827; margin-bottom: 15px; font-size: 20px; }
    .scan-info p { color: #6b7280; margin-bottom: 8px; }
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
      <h1>🛡️ CyberSec Security Report</h1>
      <p>Generated: ${new Date().toLocaleString()}</p>
    </div>

    <div class="scan-info">
      <h2>Scan Information</h2>
      <p><strong>Target URL:</strong> ${this.data.scan.target_url}</p>
      <p><strong>Scan Type:</strong> ${this.data.scan.scan_type}</p>
      <p><strong>Status:</strong> ${this.data.scan.status}</p>
      <p><strong>Scan ID:</strong> ${this.data.scan.id}</p>
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

    <div class="vulnerabilities">
      <h2>Vulnerability Details (${totalVulns} found)</h2>
      ${vulnerabilitiesHTML}
    </div>

    <div class="footer">
      <p>This report was generated by CyberSec - Advanced Security Vulnerability Scanner</p>
      <p>For more information, visit your CyberSec dashboard</p>
    </div>
  </div>
</body>
</html>
    `.trim();
  }
}
