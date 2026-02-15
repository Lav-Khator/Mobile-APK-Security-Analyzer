import os
import sys
import shutil
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename

# Add project root to path to import APKScanner modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, project_root)

from APKScanner.core.apk_analyzer import APKAnalyzer
from APKScanner.core.manifest_parser import ManifestParser
from APKScanner.core.secret_detector import SecretDetector
from APKScanner.core.network_scanner import NetworkScanner
from APKScanner.core.report_generator import ReportGenerator
from APKScanner.core.owasp_mapper import OWASPMapper

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for flash messages

# Configuration
UPLOAD_FOLDER = os.path.join(current_dir, 'uploads')
REPORT_FOLDER = os.path.join(current_dir, 'reports')
ALLOWED_EXTENSIONS = {'apk'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Start Analysis
            try:
                flash(f'Analyzing {filename}... This may take a minute.', 'info')
                
                # Initialize Analyzer
                analyzer = APKAnalyzer(filepath)
                if not analyzer.load_apk():
                    flash('Failed to load APK file.', 'error')
                    return redirect(request.url)
                
                # Results Dictionary
                results = {
                    "apk_name": filename,
                    "package_name": "",
                    "permission": [],
                    "dangerous_permission": [],
                    "manifest_analysis": {},
                    "hardcoded_secrets": [],
                    "insecure_requests": [],
                    "vulnerabilities": [],
                }
                
                # 1. Manifest
                manifest_parser = ManifestParser(analyzer)
                manifest_res = manifest_parser.parse()
                
                results['package_name'] = manifest_res.get('package_name', '')
                results['permission'] = manifest_res.get('permissions', [])
                results['dangerous_permission'] = manifest_res.get('dangerous_permission', [])
                results['manifest_analysis'] = {
                    'activities': {'all': manifest_res.get('activities', []), 'exported': manifest_res.get('exported_activity', [])},
                    'services': {'all': manifest_res.get('services', []), 'exported': manifest_res.get('exported_service', [])},
                    'receivers': {'all': manifest_res.get('receivers', []), 'exported': manifest_res.get('exported_receiver', [])},
                    'providers': {'all': manifest_res.get('providers', []), 'exported': manifest_res.get('exported_provider', [])},
                }
                
                # 2. Secrets
                # Path to false positives config
                fp_path = os.path.join(project_root, 'APKScanner', 'config', 'known_false_positives.txt')
                secret_detector = SecretDetector(fp_path)
                secrets = secret_detector.scan_apk(analyzer) # Iterate whole APK
                # Note: scan_apk() prints to stdout, we just need return value
                results['hardcoded_secrets'] = secrets
                
                # 3. Network
                network_scanner = NetworkScanner(fp_path)
                insecure_reqs = network_scanner.scan_apk(analyzer)
                results['insecure_requests'] = insecure_reqs
                
                # 4. Logging Issues
                from APKScanner.core.logging_scanner import LoggingScanner
                logging_scanner = LoggingScanner()
                logging_issues = logging_scanner.scan_apk(analyzer)

                # 5. Crypto Issues
                from APKScanner.core.crypto_scanner import CryptoScanner
                crypto_scanner = CryptoScanner()
                crypto_issues = crypto_scanner.scan_apk(analyzer)
                
                # 6. OWASP Mapping
                vulns = []
                # Map Secrets
                for secret in secrets:
                    mapped = OWASPMapper.enrich_finding(secret['type'], secret['ioc'])
                    mapped['path'] = secret['path']
                    vulns.append(mapped)
                # Map Insecure Requests
                for url in insecure_reqs:
                    mapped = OWASPMapper.enrich_finding('insecure_http', url)
                    vulns.append(mapped)
                # Map Logging Issues
                for issue in logging_issues:
                    mapped = OWASPMapper.enrich_finding('logging_usage', issue['method'])
                    mapped['description'] = issue['description']
                    mapped['severity'] = issue['severity']
                    vulns.append(mapped)
                # Map Crypto Issues
                for issue in crypto_issues:
                    mapped = OWASPMapper.enrich_finding('weak_crypto', issue['algorithm'])
                    mapped['description'] = issue['description']
                    mapped['severity'] = issue['severity']
                    vulns.append(mapped)
                # Map Exported Components
                # Map Exported Components
                for comp_type in ['activities', 'services', 'receivers', 'providers']:
                    exported = results['manifest_analysis'][comp_type]['exported']
                    key_map = {'activities': 'exported_activity', 'services': 'exported_service', 
                               'receivers': 'exported_receiver', 'providers': 'exported_provider'}
                    for comp in exported:
                        mapped = OWASPMapper.enrich_finding(key_map[comp_type], comp)
                        vulns.append(mapped)
                # Map Permissions
                for perm in results['dangerous_permission']:
                    mapped = OWASPMapper.enrich_finding('dangerous_permission', perm)
                    vulns.append(mapped)
                
                results['vulnerabilities'] = vulns
                
                # 5. Generate Report
                # Output to web/reports (ReportGenerator appends 'reports')
                report_gen = ReportGenerator(filename, current_dir)
                pdf_path = report_gen.generate_pdf_report(results)
                
                # Get just the filename of the report
                report_filename = os.path.basename(pdf_path)
                
                return redirect(url_for('result', filename=report_filename))
                
            except Exception as e:
                flash(f'An error occurred during analysis: {str(e)}', 'error')
                import traceback
                traceback.print_exc()
                return redirect(request.url)
                
    return render_template('index.html')

@app.route('/result/<filename>')
def result(filename):
    return render_template('result.html', filename=filename)

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['REPORT_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
