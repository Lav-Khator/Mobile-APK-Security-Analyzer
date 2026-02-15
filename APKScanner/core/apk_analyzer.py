import os
import re
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from colorama import Fore, Style, init

init(autoreset=True)

class APKAnalyzer:
    """
    Main APK analysis class using androguard
    """

    def __init__(self, apk_path):
        """
        Initialize the APK analyzer
        
        Args:
            apk_path: Path to the APK file
        """
        self.apk_path = apk_path
        self.apk = None
        self.analysis = None

    def load_apk(self):
        """
        Load the APK file for analysis.
        Optimized to avoid full Androguard analysis unless necessary.
        """
        try:
            print(f"{Fore.CYAN}[*] Loading APK: {self.apk_path}")
            self.apk = APK(self.apk_path)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading APK: {str(e)}")
            return False

    def get_package_name(self):
        """Get the package name from the APK"""
        if self.apk:
            return self.apk.get_package()
        return None

    def get_app_name(self):
        """Get the application name"""
        if self.apk:
            return self.apk.get_app_name()
        return None

    def get_all_files(self):
        """
        Get all files from the APK
        
        Returns:
            List of file paths in the APK
        """
        if self.apk:
            return self.apk.get_files()
        return []

    def get_dex_names(self):
        """
        Get names of all DEX files
        
        Returns:
            List of DEX filenames (e.g. classes.dex)
        """
        if self.apk:
            return [name for name in self.apk.get_files() if name.endswith('.dex')]
        return []

    def get_file_content(self, filepath):
        """
        Get content of a specific file from APK
        
        Args:
            filepath: Path to file inside APK
            
        Returns:
            File content as bytes
        """
        if self.apk:
            try:
                return self.apk.get_file(filepath)
            except:
                return None
        return None

    def get_permissions(self):
        """
        Get list of permissions from AndroidManifest.xml
        """
        if self.apk:
            try:
                return self.apk.get_permissions()
            except:
                return []
        return []

    def has_class_pattern(self, pattern_bytes):
        """
        Check if a byte pattern (e.g., class descriptor) exists in any DEX file
        
        Args:
            pattern_bytes: Byte sequence to search for
            
        Returns:
            True if found, False otherwise
        """
        if self.apk:
            try:
                for dex_content in self.apk.get_dex():
                    if pattern_bytes in dex_content:
                        return True
            except:
                pass
        return False

    def get_strings(self):
        """
        Extract all strings from the APK (using regex on DEX bytes)
        
        Returns:
            List of strings found in the APK
        """
        strings = set()
        if self.apk:
            try:
                for dex_content in self.apk.get_dex():
                    try:
                        # Regex for printable strings (4+ chars)
                        matches = re.findall(b'[\x20-\x7E]{4,}', dex_content)
                        for m in matches:
                            strings.add(m.decode('ascii', errors='ignore'))
                    except:
                        pass
            except:
                pass
        return list(strings)

    def get_manifest_xml(self):
        """
        Get the AndroidManifest.xml content
        
        Returns:
            XML content as string
        """
        if self.apk:
            try:
                xml = self.apk.get_android_manifest_xml()
                from lxml import etree
                return etree.tostring(xml, pretty_print=True, encoding='utf-8').decode('utf-8')
            except:
                return None
        return None

    def extract_source_to_directory(self, output_dir):
        """
        Extract APK contents to a directory
        
        Args:
            output_dir: Directory to extract files to
        """
        os.makedirs(output_dir, exist_ok=True)
        print(f"{Fore.CYAN}[+] Extracting APK contents to: {output_dir}")
        for file_path in self.get_all_files():
            content = self.get_file_content(file_path)
            if content:
                full_path = os.path.join(output_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                try:
                    with open(full_path, 'wb') as f:
                        f.write(content)
                except:
                     pass
        print(f"{Fore.GREEN}[+] Extraction complete")

    def get_apk_info(self):
        """
        Get basic APK information
        
        Returns:
            Dictionary with APK metadata
        """
        if not self.apk:
             return {}
        return {
             'package_name': self.apk.get_package(),
             'app_name': self.apk.get_app_name(),
             'version_name': self.apk.get_androidversion_name(),
             'version_code': self.apk.get_androidversion_code(),
             'min_sdk': self.apk.get_min_sdk_version(),
             'target_sdk': self.apk.get_target_sdk_version(),
             'permissions': self.apk.get_permissions(),
             'activities': self.apk.get_activities(),
             'services': self.apk.get_services(),
             'receivers': self.apk.get_receivers(),
             'providers': self.apk.get_providers()
        }
