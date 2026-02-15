import xml.etree.ElementTree as ET
from lxml import etree
from colorama import Fore, Style

"""
Manifest parser module - extracts security-relevant information from AndroidManifest.xml
"""

class ManifestParser:
    """
    Parse AndroidManifest.xml and extract security information
    """
    
    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.READ_HISTORY_BOOKMARKS",
        "android.permission.WRITE_HISTORY_BOOKMARKS",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.READ_LOGS",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.GET_TASKS",
        "android.permission.BLUETOOTH",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
    ]
    
    def __init__(self, apk_analyzer):
        """
        Initialize manifest parser
        
        Args:
            apk_analyzer: APKAnalyzer instance
        """
        self.apk = apk_analyzer.apk
        self.manifest_obj = None
        self.android_ns = '{http://schemas.android.com/apk/res/android}'
        
    def parse(self):
        """
        Parse the AndroidManifest.xml
        
        Returns:
            Dictionary with manifest analysis results
        """
        if not self.apk:
            return {}
        
        try:
            # Get manifest object (it's an lxml Element)
            self.manifest_obj = self.apk.get_android_manifest_xml()
        except Exception as e:
            print(f"{Fore.RED}[-] Error parsing manifest: {str(e)}")
            return {}
        
        results = {
            'package_name': self.get_package_name(),
            'permissions': self.get_permissions(),
            'dangerous_permission': self.get_dangerous_permissions(),
            'platform_build_version_code': self.get_build_version(),
            'compiled_sdk_version': self.get_sdk_version(),
            'activities': self.get_activities(),
            'exported_activity': self.get_exported_components('activity'),
            'services': self.get_services(),
            'exported_service': self.get_exported_components('service'),
            'receivers': self.get_receivers(),
            'exported_receiver': self.get_exported_components('receiver'),
            'providers': self.get_providers(),
            'exported_provider': self.get_exported_components('provider'),
        }
        
        self.print_results(results)
        return results
    
    def get_package_name(self):
        """Get package name from manifest"""
        return self.apk.get_package()
    
    def get_permissions(self):
        """Get all permissions"""
        return self.apk.get_permissions()
    
    def get_dangerous_permissions(self):
        """Get only dangerous permissions"""
        all_perms = self.get_permissions()
        return [p for p in all_perms if p in self.DANGEROUS_PERMISSIONS]
    
    def get_build_version(self):
        """Get platform build version"""
        if self.manifest_obj is not None:
            return self.manifest_obj.get('platformBuildVersionCode', 'Not available')
        return 'Not available'
    
    def get_sdk_version(self):
        """Get compiled SDK version"""
        if self.manifest_obj is not None:
            return self.manifest_obj.get('compileSdkVersion', 'Not available')
        return 'Not available'
    
    def get_activities(self):
        """Get all activities"""
        return self.apk.get_activities()
    
    def get_services(self):
        """Get all services"""
        return self.apk.get_services()
    
    def get_receivers(self):
        """Get all receivers"""
        return self.apk.get_receivers()
    
    def get_providers(self):
        """Get all providers"""
        return self.apk.get_providers()
    
    def get_exported_components(self, component_type):
        """
        Get exported components of a specific type
        
        Args:
            component_type: 'activity', 'service', 'receiver', or 'provider'
            
        Returns:
            List of exported component names
        """
        exported = []
        
        if self.manifest_obj is None:
            return exported
        
        # Find all components of the specified type
        for component in self.manifest_obj.findall(f'.//{component_type}'):
            # Check for android:exported attribute
            exported_attr = component.get(f'{self.android_ns}exported')
            name = component.get(f'{self.android_ns}name')
            
            if not name:
                continue
                
            is_exported = False
            
            if exported_attr == 'true':
                is_exported = True
            elif exported_attr == 'false':
                is_exported = False
            else:
                # Implicit export check: if <intent-filter> exists, it is exported (pre-Android 12 default)
                has_intent_filter = False
                for child in component:
                    # Check tag name, handling potential namespaces or lack thereof
                    if child.tag == 'intent-filter' or str(child.tag).endswith('intent-filter'):
                        has_intent_filter = True
                        break
                
                if has_intent_filter:
                    is_exported = True
            
            if is_exported:
                # Resolve relative names (starting with .)
                if name.startswith('.'):
                    pkg = self.get_package_name()
                    if pkg:
                        name = pkg + name
                elif '.' not in name:
                     pkg = self.get_package_name()
                     if pkg:
                         name = pkg + "." + name
                         
                exported.append(name)
        
        return exported
    
    def print_results(self, results):
        """Print manifest analysis results"""
        indent = "    "
        
        print(f"\n{Fore.CYAN}[+] Package Name:")
        print(f"{indent}{results['package_name']}\n")
        
        print(f"{Fore.CYAN}[+] Platform Build Version Code:")
        print(f"{indent}{results['platform_build_version_code']}\n")
        
        print(f"{Fore.CYAN}[+] Compile SDK Version:")
        print(f"{indent}{results['compiled_sdk_version']}\n")
        
        if results['permissions']:
            print(f"{Fore.CYAN}[+] Permissions:")
            for perm in results['permissions']:
                print(f"{indent}{perm}")
            print()
        
        if results['dangerous_permission']:
            print(f"{Fore.RED}[+] Dangerous Permissions:")
            for perm in results['dangerous_permission']:
                print(f"{indent}{perm}")
            print()
        
        if results['activities']:
            print(f"{Fore.CYAN}[+] Activities:")
            for activity in results['activities']:
                print(f"{indent}{activity}")
            print()
        
        if results['exported_activity']:
            print(f"{Fore.CYAN}[+] Exported Activities:")
            for activity in results['exported_activity']:
                print(f"{indent}{activity}")
            print()
        
        if results['services']:
            print(f"{Fore.CYAN}[+] Services:")
            for service in results['services']:
                print(f"{indent}{service}")
            print()
        
        if results['exported_service']:
            print(f"{Fore.CYAN}[+] Exported Services:")
            for service in results['exported_service']:
                print(f"{indent}{service}")
            print()
        
        if results['receivers']:
            print(f"{Fore.CYAN}[+] Receivers:")
            for receiver in results['receivers']:
                print(f"{indent}{receiver}")
            print()
        
        if results['exported_receiver']:
            print(f"{Fore.CYAN}[+] Exported Receivers:")
            for receiver in results['exported_receiver']:
                print(f"{indent}{receiver}")
            print()
        
        if results['providers']:
            print(f"{Fore.CYAN}[+] Providers:")
            for provider in results['providers']:
                print(f"{indent}{provider}")
            print()
        
        if results['exported_provider']:
            print(f"{Fore.CYAN}[+] Exported Providers:")
            for provider in results['exported_provider']:
                print(f"{indent}{provider}")
            print()
