"""
Reconnaissance Engine for Bug Bounty Automation
Handles subdomain enumeration, port scanning, and information gathering
"""

import asyncio
import json
import logging
import re
import socket
import time
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import requests
from bs4 import BeautifulSoup

class ReconnaissanceEngine:
    """Advanced reconnaissance engine for bug bounty targets"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        
        # Reconnaissance data storage
        self.subdomains = set()
        self.ports = []
        self.tech_stack = {}
        self.emails = set()
        self.social_media = []
        
    async def run_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Run complete reconnaissance on target"""
        self.logger.info(f"Starting reconnaissance for: {target}")
        
        # Initialize session
        self.session = aiohttp.ClientSession(
            headers=self.config.get('headers', {}),
            timeout=aiohttp.ClientTimeout(total=30)
        )
        
        try:
            # Phase 1: Subdomain Enumeration
            await self._enumerate_subdomains(target)
            
            # Phase 2: Port Scanning
            await self._scan_ports(target)
            
            # Phase 3: Technology Detection
            await self._detect_technologies(target)
            
            # Phase 4: Email and Social Media Discovery
            await self._discover_emails_and_social(target)
            
            # Phase 5: Content Discovery
            await self._discover_content(target)
            
            # Compile results
            results = {
                "target": target,
                "subdomains": list(self.subdomains),
                "open_ports": self.ports,
                "technology_stack": self.tech_stack,
                "emails": list(self.emails),
                "social_media": self.social_media,
                "content_discovery": self.content_discovery,
                "timestamp": time.time()
            }
            
            self.logger.info(f"Reconnaissance completed for {target}")
            return results
            
        finally:
            await self.session.close()
    
    async def _enumerate_subdomains(self, target: str):
        """Enumerate subdomains using multiple techniques"""
        self.logger.info("Starting subdomain enumeration...")
        
        # Method 1: Certificate Transparency logs
        await self._ct_logs_subdomains(target)
        
        # Method 2: DNS enumeration
        await self._dns_subdomains(target)
        
        # Method 3: Search engine enumeration
        await self._search_engine_subdomains(target)
        
        # Method 4: Third-party services
        await self._third_party_subdomains(target)
        
        self.logger.info(f"Found {len(self.subdomains)} subdomains")
    
    async def _ct_logs_subdomains(self, target: str):
        """Extract subdomains from Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        if name and name != target:
                            self.subdomains.add(name.strip())
        except Exception as e:
            self.logger.error(f"CT logs enumeration failed: {e}")
    
    async def _dns_subdomains(self, target: str):
        """Perform DNS-based subdomain enumeration"""
        wordlist = self.config.get('subdomain_wordlist', ['www', 'api', 'dev', 'test', 'admin'])
        
        async def check_subdomain(subdomain: str):
            try:
                fqdn = f"{subdomain}.{target}"
                dns.resolver.resolve(fqdn, 'A')
                self.subdomains.add(fqdn)
            except:
                pass
        
        # Run concurrent DNS checks
        tasks = [check_subdomain(word) for word in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _search_engine_subdomains(self, target: str):
        """Extract subdomains from search engines"""
        try:
            # Google dorking
            query = f"site:{target}"
            url = f"https://www.google.com/search?q={query}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    # Extract subdomains from search results
                    pattern = r'(?:https?://)?([a-zA-Z0-9.-]+\.' + re.escape(target) + r')'
                    matches = re.findall(pattern, content)
                    for match in matches:
                        self.subdomains.add(match)
        except Exception as e:
            self.logger.error(f"Search engine enumeration failed: {e}")
    
    async def _third_party_subdomains(self, target: str):
        """Use third-party services for subdomain discovery"""
        services = [
            f"https://dns.bufferover.run/dns?q=.{target}",
            f"https://jldc.me/anubis/subdomains/{target}"
        ]
        
        for service_url in services:
            try:
                async with self.session.get(service_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Extract subdomains from response
                        pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(target) + r')'
                        matches = re.findall(pattern, content)
                        for match in matches:
                            self.subdomains.add(match)
            except Exception as e:
                self.logger.error(f"Third-party service failed: {e}")
    
    async def _scan_ports(self, target: str):
        """Perform port scanning on target"""
        self.logger.info("Starting port scanning...")
        
        # Get target IP
        try:
            target_ip = socket.gethostbyname(target)
        except:
            self.logger.error(f"Could not resolve {target}")
            return
        
        # Common ports to scan
        ports_to_scan = self.config.get('ports_to_scan', [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017
        ])
        
        async def scan_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                self.ports.append(port)
            except:
                pass
        
        # Scan ports concurrently
        tasks = [scan_port(port) for port in ports_to_scan]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.info(f"Found {len(self.ports)} open ports")
    
    async def _detect_technologies(self, target: str):
        """Detect technology stack of target"""
        self.logger.info("Starting technology detection...")
        
        try:
            # HTTP headers analysis
            url = f"https://{target}"
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                self.tech_stack['headers'] = headers
                
                # Extract server information
                server = headers.get('Server', '')
                if server:
                    self.tech_stack['server'] = server
                
                # Extract X-Powered-By
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    self.tech_stack['powered_by'] = powered_by
                
                # Content analysis
                content = await response.text()
                self._analyze_content(content)
                
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
    
    def _analyze_content(self, content: str):
        """Analyze content for technology detection"""
        # Framework detection
        frameworks = {
            'WordPress': r'wp-content|wordpress',
            'Joomla': r'joomla|Joomla',
            'Drupal': r'drupal|Drupal',
            'React': r'react|React',
            'Angular': r'angular|Angular',
            'Vue.js': r'vue|Vue',
            'Laravel': r'laravel|Laravel'
        }
        
        for framework, pattern in frameworks.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.tech_stack['frameworks'] = self.tech_stack.get('frameworks', [])
                self.tech_stack['frameworks'].append(framework)
        
        # JavaScript libraries
        js_libraries = {
            'jQuery': r'jquery|jQuery',
            'Bootstrap': r'bootstrap|Bootstrap',
            'React': r'react-dom|ReactDOM'
        }
        
        for lib, pattern in js_libraries.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.tech_stack['javascript_libraries'] = self.tech_stack.get('javascript_libraries', [])
                self.tech_stack['javascript_libraries'].append(lib)
    
    async def _discover_emails_and_social(self, target: str):
        """Discover emails and social media associated with target"""
        self.logger.info("Starting email and social media discovery...")
        
        try:
            # Extract emails from website
            url = f"https://{target}"
            async with self.session.get(url) as response:
                content = await response.text()
                
                # Email pattern
                email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(target)
                emails = re.findall(email_pattern, content)
                self.emails.update(emails)
                
                # Social media detection
                social_patterns = {
                    'Twitter': r'twitter\.com/([a-zA-Z0-9_]+)',
                    'LinkedIn': r'linkedin\.com/([a-zA-Z0-9_-]+)',
                    'Facebook': r'facebook\.com/([a-zA-Z0-9_.]+)'
                }
                
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.social_media.append({
                            'platform': platform,
                            'handles': matches
                        })
                        
        except Exception as e:
            self.logger.error(f"Email/social discovery failed: {e}")
    
    async def _discover_content(self, target: str):
        """Discover interesting content and endpoints"""
        self.logger.info("Starting content discovery...")
        
        # Common paths to check
        common_paths = [
            '/admin', '/login', '/api', '/dashboard', '/wp-admin',
            '/.env', '/robots.txt', '/sitemap.xml', '/.git',
            '/admin.php', '/login.php', '/config.php'
        ]
        
        self.content_discovery = []
        
        for path in common_paths:
            try:
                url = f"https://{target}{path}"
                async with self.session.get(url, allow_redirects=False) as response:
                    if response.status in [200, 301, 302, 401, 403]:
                        self.content_discovery.append({
                            'path': path,
                            'status': response.status,
                            'url': url
                        })
            except:
                pass
        
        self.logger.info(f"Discovered {len(self.content_discovery)} interesting paths")
