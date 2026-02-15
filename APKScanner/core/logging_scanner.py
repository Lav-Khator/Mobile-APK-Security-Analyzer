import re
from colorama import Fore, Style

class LoggingScanner:
    """
    Scanner for detecting potential sensitive data leakage in logs
    (OWASP M1: Improper Platform Usage / M10: Extraneous Functionality)
    """

    def __init__(self):
        # Patterns for logging methods in DEX format
        self.patterns = [
            {
                "name": "Android Log",
                "regex": r"Landroid/util/Log;",
                "description": "Android Log class usage found. Ensure no sensitive data is logged."
            },
            {
                "name": "System.out",
                "regex": r"Ljava/io/PrintStream;",
                "description": "Standard output/error usage found (System.out/err)."
            }
        ]

    def scan_apk(self, apk_analyzer):
        """
        Scan APK for logging usage
        """
        print(f"{Fore.CYAN}[+] Scanning for Logging Usage...")
        findings = []
        
        dex_names = apk_analyzer.get_dex_names()
        if not dex_names:
            return []

        # We keep track of what we found to avoid duplicates per APK
        found_types = set()

        for dex_name in dex_names:
            content = apk_analyzer.get_file_content(dex_name)
            if not content:
                continue
            
            try:
                # Naive text search in DEX
                text = content.decode("utf-8", errors="ignore")
                
                for pattern in self.patterns:
                    if pattern["name"] in found_types:
                        continue
                        
                    if re.search(pattern["regex"], text):
                        findings.append({
                            "type": "logging_usage",
                            "method": pattern["name"],
                            "description": pattern["description"],
                            "severity": "Info" if "Debug" not in pattern["name"] else "Low"
                        })
                        found_types.add(pattern["name"])
            except Exception as e:
                pass
                
        # Sort findings
        return findings
