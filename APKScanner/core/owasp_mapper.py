"""
OWASP Mobile Top 10 Mapper module
Maps scan findings to OWASP vulnerabilities, severity levels, and remediation guidance.
"""

class OWASPMapper:
    """
    Maps findings to OWASP Mobile Top 10 (2024/2016) and provides remediation.
    """
    
    # OWASP Mobile Top 10 2024 (Primary)
    # M1: Improper Credential Usage
    # M2: Inadequate Supply Chain Security
    # M3: Insecure Authentication/Authorization
    # M4: Insufficient Input/Output Validation
    # M5: Insecure Communication
    # M6: Inadequate Privacy Controls
    # M7: Insufficient Binary Protection
    # M8: Security Misconfiguration
    # M9: Insecure Data Storage
    # M10: Insufficient Cryptography
    
    # Mapping Dictionary
    VULNERABILITY_MAP = {
        # Secrets / Hardcoded Keys
        'slack_token': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'High',
            'description': 'Hardcoded Slack token found.',
            'remediation': 'Store tokens in a secure Vault or environment variables. Never commit them to code.',
            'category': 'Hardcoded Secrets'
        },
        'slack_webhook': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'Medium',
            'description': 'Hardcoded Slack Webhook found.',
            'remediation': 'Use a proxy service or store webhook URLs in secure configuration.',
            'category': 'Hardcoded Secrets'
        },
        'google_api': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'High',
            'description': 'Hardcoded Google API Key found.',
            'remediation': 'Restrict API keys by package name and SHA-1 signature in Google Cloud Console.',
            'category': 'Hardcoded Secrets'
        },
        'google_oauth': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'High',
            'description': 'Hardcoded Google OAuth Client Secret found.',
            'remediation': 'Use standard OAuth flows. Do not embed client secrets in mobile apps.',
            'category': 'Hardcoded Secrets'
        },
        'private_ssh_key': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'Critical',
            'description': 'Private SSH Key found in code.',
            'remediation': 'Revoke the key immediately. Never embed private keys in the application.',
            'category': 'Hardcoded Secrets'
        },
        'private_rsa_key': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'Critical',
            'description': 'Private RSA Key found in code.',
            'remediation': 'Revoke the key immediately. Never embed private keys in the application.',
            'category': 'Hardcoded Secrets'
        },
        'generic_api_key': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'Medium',
            'description': 'Potential API Key found.',
            'remediation': 'Verify if this is a sensitive key. If so, move to secure storage.',
            'category': 'Hardcoded Secrets'
        },
        'generic_secret': {
            'owasp_id': 'M1: Improper Credential Usage (2024)',
            'severity': 'Medium',
            'description': 'Potential Generic Secret found.',
            'remediation': 'Verify if this is sensitive. If so, move to secure storage.',
            'category': 'Hardcoded Secrets'
        },
        
        # Network Issues
        'insecure_http': {
            'owasp_id': 'M5: Insecure Communication (2024)',
            'severity': 'Medium',
            'description': 'Cleartext HTTP URL found.',
            'remediation': 'Migrate all backend communication to HTTPS. Use `android:usesCleartextTraffic="false"` in manifest.',
            'category': 'Insecure Communication'
        },
        
        # Manifest Issues
        'exported_activity': {
            'owasp_id': 'M8: Security Misconfiguration (2024)',
            'severity': 'Medium',
            'description': 'Activity is exported and unprotected.',
            'remediation': 'Set `android:exported="false"` unless necessary. If exported, protect with permissions.',
            'category': 'Exported Component'
        },
        'exported_service': {
            'owasp_id': 'M8: Security Misconfiguration (2024)',
            'severity': 'Medium',
            'description': 'Service is exported and unprotected.',
            'remediation': 'Set `android:exported="false"`. If IPC is needed, use signature-level permissions.',
            'category': 'Exported Component'
        },
        'exported_provider': {
            'owasp_id': 'M9: Insecure Data Storage (2024)',
            'severity': 'High',
            'description': 'Content Provider is exported.',
            'remediation': 'Ensure `android:exported="false"`. Verify `android:grantUriPermissions` settings.',
            'category': 'Exported Component'
        },
        'exported_receiver': {
            'owasp_id': 'M8: Security Misconfiguration (2024)',
            'severity': 'Medium',
            'description': 'Broadcast Receiver is exported.',
            'remediation': 'Set `android:exported="false"`. Validate input Intents carefully.',
            'category': 'Exported Component'
        },
        'dangerous_permission': {
            'owasp_id': 'M6: Inadequate Privacy Controls (2024)',
            'severity': 'Info',
            'description': 'Application requests dangerous permission.',
            'remediation': 'Review if this permission is strictly necessary. Follow least privilege principle.',
            'category': 'Permission'
        },
        'debuggable': {
            'owasp_id': 'M8: Security Misconfiguration (2024)',
            'severity': 'High',
            'description': 'Application is debuggable.',
            'remediation': 'Set `android:debuggable="false"` in AndroidManifest.xml for production builds.',
            'category': 'Misconfiguration'
        },
        'allow_backup': {
            'owasp_id': 'M9: Insecure Data Storage (2024)',
            'severity': 'Medium',
            'description': 'Application allows backup.',
            'remediation': 'Set `android:allowBackup="false"` to prevent data extraction via ADB backup.',
            'category': 'Misconfiguration'
        },
        'logging_usage': {
            'owasp_id': 'M1: Improper Platform Usage (2024)',
            'severity': 'Info',
            'description': 'Detection of Android logging methods (Log.d, Log.e, System.out).',
            'remediation': 'Ensure no sensitive data (PII, tokens, passwords) is written to logs. Remove debug logs in production.',
            'category': 'Sensitive Data Leakage'
        },
        'weak_crypto': {
            'owasp_id': 'M10: Insufficient Cryptography (2024)',
            'severity': 'High',
            'description': 'Weak cryptographic algorithm or mode detected.',
            'remediation': 'Use strong algorithms (AES-GCM, SHA-256). Avoid ECB mode, DES, MD5, RC4.',
            'category': 'Weak Cryptography'
        }
    }

    @classmethod
    def get_details(cls, key):
        """
        Get OWASP details for a specific vulnerability key.
        Returns a dict with 'owasp_id', 'severity', 'description', 'remediation'.
        """
        # Default fallback
        default_details = {
            'owasp_id': 'Unknown',
            'severity': 'Info',
            'description': 'Security finding.',
            'remediation': 'Review manually and assess risk.',
            'category': 'General'
        }
        
        # Check explicit mapping
        if key in cls.VULNERABILITY_MAP:
            return cls.VULNERABILITY_MAP[key]
            
        # Partial match fallback (e.g., for specific API keys not explicitly listed but following pattern)
        if 'api' in key or 'key' in key or 'token' in key or 'secret' in key:
             return cls.VULNERABILITY_MAP['generic_api_key']
             
        return default_details

    @classmethod
    def enrich_finding(cls, finding_type, value=None):
        """
        Enrich a finding with OWASP metadata.
        """
        details = cls.get_details(finding_type)
        return {
            'type': finding_type,
            'value': value,
            'owasp': details['owasp_id'],
            'severity': details['severity'],
            'description': details['description'],
            'remediation': details['remediation'],
            'category': details['category']
        }
