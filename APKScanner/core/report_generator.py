import json
import os
from datetime import datetime
from colorama import Fore, Style
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

"""
Report generator module - creates JSON, HTML, PDF, and TXT reports
"""

class ReportGenerator:
    """
    Generate security scan reports in multiple formats
    """
    
    def __init__(self, apk_name, output_path=None):
        """
        Initialize report generator
        
        Args:
            apk_name: Name of the APK file
            output_path: Optional output directory
        """
        self.apk_name = apk_name
        self.output_path = output_path if output_path else os.getcwd()
    
    def clean_apk_name(self):
        """Remove .apk extension from filename"""
        import re
        cleaned = re.sub(r'(\.com|\.apk)', '', self.apk_name)
        return cleaned
    
    def generate_json_report(self, results):
        """
        Generate JSON report
        
        Args:
            results: Dictionary with scan results
        """
        clean_name = self.clean_apk_name()
        reports_dir = os.path.join(self.output_path, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        json_path = os.path.join(reports_dir, f"report_{clean_name}.json")
        
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"{Fore.CYAN}[+] Generated JSON report - {json_path}")
        return json_path
    
    def generate_txt_report(self, results):
        """
        Generate TXT report
        
        Args:
            results: Dictionary with scan results
        """
        clean_name = self.clean_apk_name()
        reports_dir = os.path.join(self.output_path, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        txt_path = os.path.join(reports_dir, f"report_{clean_name}.txt")
        
        report = self._build_text_report(results)
        
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"{Fore.CYAN}[+] Generated TXT report - {txt_path}")
        return txt_path

    def generate_pdf_report(self, results):
        """
        Generate PDF report using ReportLab
        
        Args:
            results: Dictionary with scan results
        """
        clean_name = self.clean_apk_name()
        reports_dir = os.path.join(self.output_path, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        pdf_path = os.path.join(reports_dir, f"report_{clean_name}.pdf")
        
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=72, leftMargin=72,
            topMargin=72, bottomMargin=18
        )
        
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Justify', alignment=1))
        
        # Professional Heading Style
        title_style = ParagraphStyle(
            name='ReportTitle',
            parent=styles['Heading1'],
            fontSize=24,
            leading=30,
            alignment=1, # Center
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        h1_style = ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            leading=20,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.black,
            borderPadding=(0, 0, 5, 0), # Add underline effect manually if needed, or just color
            borderWidth=0
        )
        
        normal_style = styles['Normal']
        normal_style.fontSize = 11
        normal_style.leading = 14
        
        code_style = ParagraphStyle(
            name='Code',
            parent=styles['Code'],
            fontSize=10,
            leading=12,
            textColor=colors.darkblue,
            backColor=colors.white
        )

        val_style = ParagraphStyle(
             name='Value',
             parent=normal_style,
             textColor=colors.darkred
        )

        story = []
        
        # Title Page
        story.append(Paragraph(f"APK Security Report", title_style))
        story.append(Paragraph(f"{self.apk_name}", styles['Heading2']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Paragraph(f"<b>Package:</b> {results.get('package_name', 'N/A')}", normal_style))
        story.append(Paragraph("<b>Tool:</b> APK Armor - Attack on Anomalies", normal_style))
        story.append(Spacer(1, 24))
        
        # Executive Summary / Vulnerabilities
        story.append(Paragraph("Security Vulnerabilities", h1_style))
        
        vulns = results.get('vulnerabilities', [])
        if vulns:
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
            
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get('severity', 'Info').upper()
                
                # Color coding for severity header
                if severity in ['HIGH', 'CRITICAL']:
                    sev_color = colors.red
                elif severity == 'MEDIUM':
                    sev_color = colors.orange
                else:
                    sev_color = colors.green
                
                # Finding Header
                story.append(Paragraph(f"{i}. {vuln.get('owasp', 'Finding')}", 
                                     ParagraphStyle('FindingTitle', parent=styles['Heading3'], fontSize=12, spaceAfter=2)))
                
                # Severity Badge (Text)
                sev_text = f"<font color='{sev_color.hexval()}'><b>[{severity}]</b></font>"
                story.append(Paragraph(sev_text, normal_style))
                
                # Details
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Type:</b> {vuln.get('category', 'General')}", normal_style))
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'N/A')}", normal_style))
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'N/A')}", normal_style))
                
                if vuln.get('path'):
                     story.append(Spacer(1, 4))
                     story.append(Paragraph(f"<b>Location:</b> {vuln.get('path')}", code_style))
                
                if vuln.get('value'):
                    val = str(vuln.get('value'))
                    # Wrap long text
                    if len(val) > 80: val = val[:77] + "..."
                    story.append(Spacer(1, 4))
                    story.append(Paragraph(f"<b>Value:</b> {val}", code_style))

                story.append(Spacer(1, 12))
                # Divider
                story.append(Paragraph("_" * 60, ParagraphStyle('Divider', parent=normal_style, alignment=1, textColor=colors.lightgrey)))
                story.append(Spacer(1, 12))
        else:
            story.append(Paragraph("No major vulnerabilities found.", normal_style))
            
        story.append(Spacer(1, 12))
        
        # Permissions
        story.append(Paragraph("Permissions", h1_style))
        perms = results.get('permission', [])
        dang_perms = results.get('dangerous_permission', [])
        
        if perms:
            for perm in perms:
                if perm in dang_perms:
                     story.append(Paragraph(f"<font color='red'>• {perm} [DANGEROUS]</font>", normal_style))
                else:
                     story.append(Paragraph(f"• {perm}", normal_style))
        else:
            story.append(Paragraph("No permissions requested.", normal_style))
            
        story.append(Spacer(1, 12))

        # Manifest Components Overview
        story.append(Paragraph("Manifest Components", h1_style))
        manifest = results.get('manifest_analysis', {})
        
        # create data for table
        table_data = [['Component', 'Total', 'Exported']]
        for c_type in ['activities', 'services', 'receivers', 'providers']:
            total = len(manifest.get(c_type, {}).get('all', []))
            exported = len(manifest.get(c_type, {}).get('exported', []))
            table_data.append([c_type.capitalize(), str(total), str(exported)])
            
        t = Table(table_data, colWidths=[200, 100, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(t)
        
        story.append(Spacer(1, 24))
        
        # Manifest Details (Exported only to save space, or all?)
        # User wants "technical document". Let's list EXPORTED components specifically.
        story.append(Paragraph("Exported Components (Attack Surface)", h1_style))
        has_exported = False
        for c_type in ['activities', 'services', 'receivers', 'providers']:
            exported_list = manifest.get(c_type, {}).get('exported', [])
            if exported_list:
                has_exported = True
                story.append(Paragraph(f"<b>{c_type.capitalize()}</b>", styles['Heading3']))
                for comp in exported_list:
                    story.append(Paragraph(f"• {comp}", code_style))
                    story.append(Spacer(1, 4))
                story.append(Spacer(1, 6))
        
        if not has_exported:
             story.append(Paragraph("No exported components found.", normal_style))

        # Secrets Section
        story.append(Paragraph("Hardcoded Secrets", h1_style))
        secrets = results.get('hardcoded_secrets', [])
        if secrets:
            for s in secrets:
                 story.append(Paragraph(f"• <b>{s['type']}</b> found in <i>{s.get('path', 'unknown')}</i>", normal_style))
                 story.append(Paragraph(f"  Value: {s.get('ioc', '')}", code_style))
                 story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No secrets found.", normal_style))

        # Network Section
        story.append(Paragraph("Network Security", h1_style))
        insecure = results.get('insecure_requests', [])
        if insecure:
            for url in insecure:
                story.append(Paragraph(f"• Insecure URL: {url}", code_style))
        else:
            story.append(Paragraph("No insecure URLs found.", normal_style))

        story.append(Spacer(1, 24))
        story.append(Paragraph("End of Report", ParagraphStyle('End', parent=normal_style, alignment=1, textColor=colors.grey)))
            
        doc.build(story)
        print(f"{Fore.CYAN}[+] Generated PDF report - {pdf_path}")
        return pdf_path
    
    def _build_text_report(self, results):
        """Build text report content"""
        report = "=" * 80 + "\n"
        report += f"APK Security Scan Report\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += "=" * 80 + "\n\n"
        
        report += "Basic Info\n"
        report += "-" * 80 + "\n"
        report += f"APK Name: {results.get('apk_name', 'N/A')}\n"
        report += f"Package Name: {results.get('package_name', 'N/A')}\n\n"
        
        # OWASP Vulnerability Summary (NEW)
        report += "Security Vulnerabilities (OWASP Mobile Top 10)\n"
        report += "-" * 80 + "\n"
        vulns = results.get('vulnerabilities', [])
        
        if vulns:
            # Sort by severity (High -> Medium -> Low/Info)
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
            
            for i, vuln in enumerate(vulns, 1):
                report += f"{i}. [{vuln.get('severity', 'Info').upper()}] {vuln.get('owasp', 'Unknown')}\n"
                report += f"   Type: {vuln.get('category', 'General')}\n"
                report += f"   Description: {vuln.get('description', 'N/A')}\n"
                report += f"   Remediation: {vuln.get('remediation', 'N/A')}\n"
                if vuln.get('path'):
                    report += f"   Location: {vuln.get('path')}\n"
                if vuln.get('value'):
                     # Truncate long values
                    val = str(vuln.get('value'))
                    if len(val) > 50: val = val[:47] + "..."
                    report += f"   Value: {val}\n"
                report += "\n"
        else:
            report += "No major vulnerabilities found.\n"
        report += "\n"
        
        # Permissions
        report += "Permissions\n"
        report += "-" * 80 + "\n"
        perms = results.get('permission', [])
        if perms:
            for perm in perms:
                report += f"- {perm}\n"
        else:
            report += "No permissions found.\n"
        report += "\n"
        
        # Detailed Sections (Manifest, Secrets, Network)
        # Manifest Analysis
        manifest = results.get('manifest_analysis', {})
        for component_type in ['activities', 'services', 'receivers', 'providers']:
            report += f"{component_type.capitalize()}\n"
            report += "-" * 80 + "\n"
            components = manifest.get(component_type, {}).get('all', [])
            exported = manifest.get(component_type, {}).get('exported', [])
            
            if components:
                for comp in components:
                    if comp in exported:
                        report += f"- {comp} [EXPORTED] (See Vulnerabilities)\n"
                    else:
                        report += f"- {comp}\n"
            else:
                report += f"No {component_type} found.\n"
            report += "\n"

        # Insecure Connections
        report += "Insecure Network Connections\n"
        report += "-" * 80 + "\n"
        insecure = results.get('insecure_requests', [])
        if insecure:
            for url in insecure:
                if ',' in url:
                    sub_urls = url.split(',')
                    for sub in sub_urls:
                        if sub.strip():
                            report += f"- {sub.strip()}\n"
                else:
                    report += f"- {url}\n"
        else:
            report += "No insecure connections found.\n"
        report += "\n"
        
        report += "=" * 80 + "\n"
        report += "End of Report\n"
        report += "=" * 80 + "\n"
        
        return report
