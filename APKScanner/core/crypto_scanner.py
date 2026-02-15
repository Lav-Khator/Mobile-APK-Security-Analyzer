import re
from colorama import Fore, Style

class CryptoScanner:
    """
    Scanner for detecting weak cryptographic algorithms (OWASP M10)
    """

    def __init__(self):
        # Patterns for weak algorithms
        # We look for strings passed to Cipher.getInstance() or MessageDigest.getInstance()
        self.weak_algos = {
            'DES': {
                'pattern': r'DES',
                'description': 'Weak algorithm (DES) usage found. Use AES-GCM instead.',
                'severity': 'High'
            },
            '3DES': {
                'pattern': r'DESede',
                'description': 'Weak algorithm (3DES) usage found. Use AES-GCM instead.',
                'severity': 'Medium'
            },
            'RC4': {
                'pattern': r'RC4',
                'description': 'Weak algorithm (RC4) usage found. Use AES-GCM instead.',
                'severity': 'High'
            },
            'Blowfish': {
                'pattern': r'Blowfish',
                'description': 'Weak algorithm (Blowfish) usage found. Use AES-GCM instead.',
                'severity': 'Medium'
            },
            'MD5': {
                'pattern': r'MD5',
                'description': 'Weak hash (MD5) usage found. Use SHA-256 or stronger.',
                'severity': 'Medium'
            },
            'SHA1': {
                'pattern': r'SHA-1',
                'description': 'Weak hash (SHA-1) usage found. Use SHA-256 or stronger.',
                'severity': 'Low'
            },
            'ECB': {
                'pattern': r'ECB',
                'description': 'Weak block mode (ECB) usage found. Use GCM or CBC with random IV.',
                'severity': 'High'
            },
            'NoPadding': {
                'pattern': r'NoPadding',
                'description': 'Cipher usage without padding found. Ensure this is intended.',
                'severity': 'Medium'
            }
        }

    def scan_apk(self, apk_analyzer):
        """
        Scan APK for weak crypto
        """
        print(f"{Fore.CYAN}[+] Scanning for Weak Cryptography...")
        findings = []
        
        dex_names = apk_analyzer.get_dex_names()
        if not dex_names:
            return []

        # We keep track of what we found to avoid duplicates per APK
        found_algos = set()

        for dex_name in dex_names:
            content = apk_analyzer.get_file_content(dex_name)
            if not content:
                continue
            
            try:
                # Naive text search in DEX strings
                # This works because "AES/ECB/PKCS5Padding" is stored as a string constant
                text = content.decode("utf-8", errors="ignore")
                
                # Check for each weak algo
                for algo_name, info in self.weak_algos.items():
                    if algo_name in found_algos:
                        continue
                        
                    # We search for the pattern. 
                    # If present, it's likely used in Cipher.getInstance() or similar.
                    if re.search(info['pattern'], text, re.IGNORECASE):
                        findings.append({
                            "type": "weak_crypto",
                            "algorithm": algo_name,
                            "description": info['description'],
                            "severity": info['severity']
                        })
                        found_algos.add(algo_name)
                        
            except Exception as e:
                pass
                
        return findings
