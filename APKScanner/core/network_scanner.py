import os
import re
from colorama import Fore, Style

"""
Network scanner module - detects insecure network communications
"""

class NetworkScanner:
    """
    Scan for insecure network communications (HTTP, FTP, etc.)
    """
    
    # Strict: only cleartext HTTP
    INSECURE_PATTERN = r"http://[^\s\"'<>]+"
    
    # Known documentation / non-runtime domains
    IGNORE_DOMAINS = [
        "slf4j.org",
        "xmlpull.org",
        "example.com",
        "java.sun.com",
        "amazon.com",
        "play.google.com", 
        "schemas.android.com",
        "schemas.google.com",
        "www.w3.org"
    ]
    
    def __init__(self, false_positives_file='config/known_false_positives.txt'):
        """
        Initialize network scanner
        
        Args:
            false_positives_file: Path to false positives file
        """
        self.false_positives = self.load_false_positives(false_positives_file)
        self.pattern = re.compile(self.INSECURE_PATTERN)
    
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
    
    def is_documentation_url(self, url):
        """Check if URL is a known documentation/placeholder domain"""
        for domain in self.IGNORE_DOMAINS:
            if domain in url:
                return True
        return False

    def is_placeholder_url(self, url):
        """Check if URL contains placeholder characters"""
        if "%s" in url or "%d" in url:
            return True
        if "#" in url: # often anchors in docs
            return True
        return False

    def is_false_positive(self, url):
        """Check if a URL is a known false positive"""
        # 1. Check Hardcoded domains
        if self.is_documentation_url(url):
            return True
        # 2. Check Placeholders
        if self.is_placeholder_url(url):
            return True
        # 3. Check loaded patterns
        for fp_pattern in self.false_positives:
            if fp_pattern.match(url):
                return True
        return False
    
    def scan_apk(self, apk_analyzer):
        """
        Scan APK for insecure network connections (DEX ONLY)
        
        Args:
            apk_analyzer: APKAnalyzer instance
            
        Returns:
            List of insecure URLs found
        """
        print(f"{Fore.CYAN}[+] Scanning DEX for cleartext HTTP usage")
        
        # 1. Check for INTERNET permission
        permissions = apk_analyzer.get_permissions()
        if 'android.permission.INTERNET' not in permissions:
             print(f"{Fore.YELLOW}[!] No INTERNET permission found. Skipping network scan.")
             return []
             
        insecure_urls = []
        
        # 2. Scan ONLY DEX files
        dex_names = apk_analyzer.get_dex_names()
        if not dex_names:
            print(f"{Fore.YELLOW}[!] No DEX files found.")
            return []
            
        for dex_name in dex_names:
            content = apk_analyzer.get_file_content(dex_name)
            if not content:
                continue

            try:
                # DEX is binary, but strings are usually visible. 
                # decode with ignore to get strings
                text = content.decode("utf-8", errors="ignore")
                matches = self.pattern.findall(text)

                for match in matches:
                    if not self.is_false_positive(match):
                        insecure_urls.append(match)
            except:
                pass
        
        # Remove duplicates
        insecure_urls = list(set(insecure_urls))
        
        # Print results
        for url in insecure_urls:
            print(f"    {url}")
        
        return insecure_urls
