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
        
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = styles['Title']
        story.append(Paragraph(f"APK Security Scan Report: {self.apk_name}", title_style))
        story.append(Spacer(1, 12))
        
        # Metadata
        normal_style = styles['Normal']
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Paragraph(f"Package Name: {results.get('package_name', 'N/A')}", normal_style))
        story.append(Spacer(1, 12))
        
        # Vulnerabilities
        h2_style = styles['Heading2']
        story.append(Paragraph("Security Vulnerabilities (OWASP Mobile Top 10)", h2_style))
        story.append(Spacer(1, 6))
        
        vulns = results.get('vulnerabilities', [])
        if vulns:
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
            
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get('severity', 'Info').upper()
                color = colors.red if severity in ['HIGH', 'CRITICAL'] else colors.orange if severity == 'MEDIUM' else colors.black
                
                s = f"<b>{i}. [{severity}] {vuln.get('owasp', 'Unknown')}</b><br/>"
                s += f"Type: {vuln.get('category', 'General')}<br/>"
                s += f"Description: {vuln.get('description', 'N/A')}<br/>"
                s += f"Remediation: {vuln.get('remediation', 'N/A')}<br/>"
                if vuln.get('path'):
                    s += f"Location: <i>{vuln.get('path')}</i><br/>"
                
                p = Paragraph(s, normal_style)
                story.append(p)
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No major vulnerabilities found.", normal_style))
            
        story.append(Spacer(1, 12))
        
        # Permissions
        story.append(Paragraph("Permissions", h2_style))
        perms = results.get('permission', [])
        if perms:
            for perm in perms:
                story.append(Paragraph(f"- {perm}", normal_style))
        else:
            story.append(Paragraph("No permissions found.", normal_style))
            
        story.append(Spacer(1, 12))

        # Manifest Analysis
        manifest = results.get('manifest_analysis', {})
        for component_type in ['activities', 'services', 'receivers', 'providers']:
            story.append(Paragraph(component_type.capitalize(), h2_style))
            components = manifest.get(component_type, {}).get('all', [])
            exported = manifest.get(component_type, {}).get('exported', [])
            
            if components:
                # Use a bullet list or just paragraphs
                for comp in components:
                    if comp in exported:
                        p = Paragraph(f"- {comp} <font color='red'>[EXPORTED]</font>", normal_style)
                    else:
                        p = Paragraph(f"- {comp}", normal_style)
                    story.append(p)
            else:
                story.append(Paragraph(f"No {component_type} found.", normal_style))
            story.append(Spacer(1, 6))

        story.append(Spacer(1, 6))

        # Hardcoded Secrets
        story.append(Paragraph("Hardcoded Secrets", h2_style))
        secrets = results.get('hardcoded_secrets', [])
        if secrets:
            for secret in secrets:
                # Wrap long values
                val = str(secret.get('ioc', ''))
                if len(val) > 60: val = val[:57] + "..."
                s = f"<b>Type:</b> {secret.get('type')}<br/>"
                s += f"<b>Value:</b> {val}<br/>"
                if secret.get('path'):
                    s += f"<b>Path:</b> {secret.get('path')}<br/>"
                
                story.append(Paragraph(s, normal_style))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No hardcoded secrets found.", normal_style))
            
        story.append(Spacer(1, 12))

        # Insecure Network
        story.append(Paragraph("Insecure Network Connections", h2_style))
        insecure = results.get('insecure_requests', [])
        if insecure:
            for url in insecure:
                # Split by comma if present (fix for merged DEX strings)
                if ',' in url:
                    sub_urls = url.split(',')
                    for sub in sub_urls:
                        if sub.strip():
                            story.append(Paragraph(f"- {sub.strip()}", normal_style))
                else:
                    # Wrap long URLs
                    story.append(Paragraph(f"- {url}", normal_style))
        else:
            story.append(Paragraph("No insecure connections found.", normal_style))
            
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
