#!/usr/bin/env python3
import os
import sys
import argparse
import time
from colorama import Fore, Style, init

# Add core modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.apk_analyzer import APKAnalyzer
from core.manifest_parser import ManifestParser
from core.secret_detector import SecretDetector
from core.network_scanner import NetworkScanner
from core.report_generator import ReportGenerator
from core.owasp_mapper import OWASPMapper

init(autoreset=True)

"""
    Title:      APKScanner
    Desc:       Python-native Android security scanner
    Author:     Startx
    Version:    1.0.0
"""

def parse_args():
    """Parse command-line arguments"""
    
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}APKSecurity: Python-native Android security scanner{Style.RESET_ALL}",
        epilog="For more information, visit: https://github.com/Lav-Khator/Mobile-APK-Security-Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-apk',
        metavar='APK',
        type=str,
        required=True,
        help='Path to the APK file to be analyzed.'
    )
    
    parser.add_argument(
        '-report',
        choices=['json', 'txt', 'pdf'],
        default='json',
        help='Format of the report to be generated. Default is JSON.'
    )
    
    parser.add_argument(
        '-o',
        metavar='output path',
        type=str,
        help='Output directory for reports (default: current directory)'
    )
    
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='APKScanner v1.0.0 (Python-native)',
        help='Display the version of APKScanner.'
    )
    
    return parser.parse_args()

def main():
    """Main execution function"""
    try:
        args = parse_args()
        
        apk_path = args.apk
        apk_name = os.path.basename(apk_path)
        
        # Check if APK exists
        if not os.path.isfile(apk_path):
            print(f"{Fore.RED}[-] ERROR: APK file not found: {apk_path}")
            sys.exit(1)
        
        print(f"{Fore.GREEN}[+] APK file found: {apk_path}{Style.RESET_ALL}\n")
        time.sleep(0.5)
        
        # Initialize results dictionary
        results_dict = {
            "apk_name": apk_name,
            "package_name": "",
            "permission": [],
            "dangerous_permission": [],
            "manifest_analysis": {},
            "hardcoded_secrets": [],
            "insecure_requests": [],
            "vulnerabilities": [],  # aggregated list of all security findings
        }
        
        # Step 1: Load and analyze APK
        print(f"{Fore.CYAN}{'='*80}")
        print(f"STEP 1: Loading APK")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        analyzer = APKAnalyzer(apk_path)
        if not analyzer.load_apk():
            print(f"{Fore.RED}[-] Failed to load APK")
            sys.exit(1)
        
        # Step 2: Parse AndroidManifest.xml
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 2: Analyzing AndroidManifest.xml")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        manifest_parser = ManifestParser(analyzer)
        manifest_results = manifest_parser.parse()
        
        results_dict['package_name'] = manifest_results.get('package_name', '')
        results_dict['permission'] = manifest_results.get('permissions', [])
        results_dict['dangerous_permission'] = manifest_results.get('dangerous_permission', [])
        results_dict['manifest_analysis'] = {
            'activities': {
                'all': manifest_results.get('activities', []),
                'exported': manifest_results.get('exported_activity', []),
            },
            'services': {
                'all': manifest_results.get('services', []),
                'exported': manifest_results.get('exported_service', []),
            },
            'receivers': {
                'all': manifest_results.get('receivers', []),
                'exported': manifest_results.get('exported_receiver', []),
            },
            'providers': {
                'all': manifest_results.get('providers', []),
                'exported': manifest_results.get('exported_provider', []),
            },
        }
        
        # Get base directory of the scanner
        base_dir = os.path.dirname(os.path.abspath(__file__))
        fp_path = os.path.join(base_dir, 'config', 'known_false_positives.txt')
        
        # Step 3: Scan for hardcoded secrets
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 3: Scanning for Hardcoded Secrets")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        secret_detector = SecretDetector(fp_path)
        secrets = secret_detector.scan_apk(analyzer)
        results_dict['hardcoded_secrets'] = secrets
        
        # Step 4: Scan for insecure network connections
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 4: Scanning for Insecure Network Connections")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        network_scanner = NetworkScanner(fp_path)
        insecure_requests = network_scanner.scan_apk(analyzer)
        results_dict['insecure_requests'] = insecure_requests

        # Step 5: Scan for Logging Usage
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 5: Scanning for Logging Usage")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        from core.logging_scanner import LoggingScanner
        logging_scanner = LoggingScanner()
        logging_issues = logging_scanner.scan_apk(analyzer)
        # We don't need to store raw logging_issues in results_dict if we map them immediately, 
        # but let's store them for completeness if needed later
        results_dict['logging_issues'] = logging_issues
        
        # Step 6: Scan for Weak Cryptography
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 6: Scanning for Weak Cryptography")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        from core.crypto_scanner import CryptoScanner
        crypto_scanner = CryptoScanner()
        crypto_issues = crypto_scanner.scan_apk(analyzer)
        results_dict['crypto_issues'] = crypto_issues
        
        # Step 7: Map Findings to OWASP
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 7: Mapping Findings to OWASP Top 10")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        vulns = []
        
        # 1. Map Secrets
        for secret in secrets:
            mapped = OWASPMapper.enrich_finding(secret['type'], secret['ioc'])
            mapped['path'] = secret['path']
            vulns.append(mapped)
            
        # 2. Map Insecure Requests
        for url in insecure_requests:
            mapped = OWASPMapper.enrich_finding('insecure_http', url)
            vulns.append(mapped)
            
        # 3. Map Exported Components
        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            exported = results_dict['manifest_analysis'][comp_type]['exported']
            key_map = {
                'activities': 'exported_activity',
                'services': 'exported_service',
                'receivers': 'exported_receiver',
                'providers': 'exported_provider'
            }
            for comp in exported:
                mapped = OWASPMapper.enrich_finding(key_map[comp_type], comp)
                vulns.append(mapped)
        
        # 4. Map Dangerous Permissions
        for perm in results_dict['dangerous_permission']:
            mapped = OWASPMapper.enrich_finding('dangerous_permission', perm)
            vulns.append(mapped)
            
        # 5. Map Logging Issues
        if 'logging_issues' in results_dict:
            for issue in results_dict['logging_issues']:
                mapped = OWASPMapper.enrich_finding('logging_usage', issue['method'])
                mapped['description'] = issue['description']
                mapped['severity'] = issue['severity']
                vulns.append(mapped)
            
        # 6. Map Crypto Issues
        if 'crypto_issues' in results_dict:
            for issue in results_dict['crypto_issues']:
                mapped = OWASPMapper.enrich_finding('weak_crypto', issue['algorithm'])
                mapped['description'] = issue['description']
                mapped['severity'] = issue['severity']
                vulns.append(mapped)
            
        results_dict['vulnerabilities'] = vulns
        print(f"{Fore.GREEN}[+] mapped {len(vulns)} vulnerabilities to OWASP standards")
        
        # Step 5: Generate report
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"STEP 7: Generating Report")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        output_path = args.o if args.o else os.getcwd()
        report_gen = ReportGenerator(apk_name, output_path)
        
        if args.report == 'json':
            report_gen.generate_json_report(results_dict)
        elif args.report == 'txt':
            report_gen.generate_txt_report(results_dict)
        elif args.report == 'pdf':
            report_gen.generate_pdf_report(results_dict)
        
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"Scan Complete!")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
