import os
import re
from colorama import Fore, Style

"""
Secret detector module - finds hardcoded secrets and sensitive information
"""

class SecretDetector:
    """
    Detect hardcoded secrets and sensitive information in APK files
    """
    
    # Secret patterns
    PATTERNS = {
        "slack_token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        "slack_webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "facebook_oauth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\s][0-9a-f]{32}['\"\s]",
        "twitter_oauth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\s][0-9a-zA-Z]{35,44}['\"\s]",
        "twitter_access_token": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
        "heroku_api": r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "mailgun_api": r"key-[0-9a-zA-Z]{32}",
        "mailchamp_api": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "picatic_api": r"sk_live_[0-9a-z]{32}",
        "google_oauth_id": r"[0-9(+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "google_api": r"AIza[0-9A-Za-z-_]{35}",
        "google_captcha": r"^6[0-9a-zA-Z_-]{39}$",
        "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
        "amazon_aws_access_key_id": r"AKIA[0-9A-Z]{16}",
        "amazon_mws_auth_token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "amazonaws_url": r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com",
        "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "twilio_api_key": r"\bSK[0-9a-fA-F]{32}\b",
        "twilio_account_sid": r"\bAC[a-zA-Z0-9_\-]{32}\b",
        "twilio_app_sid": r"\bAP[a-zA-Z0-9_\-]{32}\b",
        "paypal_braintree_access_token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "square_oauth_secret": r"sq0csp-[ 0-9A-Za-z\-_]{43}",
        "square_access_token": r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
        "stripe_standard_api": r"sk_live_[0-9a-zA-Z]{24}",
        "stripe_restricted_api": r"rk_live_[0-9a-zA-Z]{24}",
        "github_access_token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
        "private_ssh_key": r"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END PRIVATE KEY-----",
        "private_rsa_key": r"-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END RSA PRIVATE KEY-----",
        "gpg_private_key_block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
    }
    
    def __init__(self, false_positives_file='config/known_false_positives.txt'):
        """
        Initialize secret detector
        
        Args:
            false_positives_file: Path to false positives file
        """
        self.false_positives = self.load_false_positives(false_positives_file)
        self.compiled_patterns = [(key, re.compile(pattern)) for key, pattern in self.PATTERNS.items()]
    
    def load_false_positives(self, filepath):
        """Load known false positives from file"""
        false_positives = []
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            false_positives.append(re.compile(line))
                        except:
                            pass
        return false_positives
    
    def is_false_positive(self, match):
        """Check if a match is a known false positive"""
        for fp_pattern in self.false_positives:
            if fp_pattern.match(match):
                return True
        return False
    
    def scan_text(self, text, filepath=""):
        """
        Scan text for secrets
        
        Args:
            text: Text to scan
            filepath: Optional filepath for context
            
        Returns:
            List of findings
        """
        findings = []
        
        # Common public IPs to ignore
        IGNORED_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '127.0.0.1', '0.0.0.0'}
        
        for key, compiled_pattern in self.compiled_patterns:
            matches = list(set(compiled_pattern.findall(text)))
            for match in matches:
                # Filter 1: Ignore known false positives (from config file)
                if self.is_false_positive(match):
                    continue
                    
                # Filter 2: Ignore uppercase constants (e.g. ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                if match.isupper() and '_' in match and len(match) > 10:
                    continue
                    
                # Filter 3: Ignore specific public IPs
                if key == 'ip_address':
                    if match in IGNORED_IPS:
                        continue
                    # Ignore version numbers (e.g. 9.17.3.0) - heuristic: usually appear in specific contexts
                    # For now, we rely on the specific list, but we can add logic here if needed.
                
                findings.append({
                    'type': key,
                    'ioc': match,
                    'path': filepath
                })
        
        return findings
    
    def scan_apk(self, apk_analyzer):
        """
        Scan entire APK for secrets
        
        Args:
            apk_analyzer: APKAnalyzer instance
            
        Returns:
            List of all secret findings
        """
        print(f"{Fore.CYAN}[+] Extracting all hardcoded secrets")
        
        all_findings = []
        indent = "    "
        
        # Excluded file extensions
        excluded_extensions = ['.ttf', '.otf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.gradle']
        
        # Scan all files in APK
        for filepath in apk_analyzer.get_all_files():
            _, ext = os.path.splitext(filepath)
            if ext.lower() in excluded_extensions:
                continue
            
            content = apk_analyzer.get_file_content(filepath)
            if content:
                try:
                    # Try to decode as text
                    text = content.decode('utf-8', errors='ignore')
                    findings = self.scan_text(text, filepath)
                    
                    for finding in findings:
                        print(f"{indent}{finding['type']}: {finding['ioc']}")
                        all_findings.append(finding)
                except:
                    pass
        
        return all_findings
