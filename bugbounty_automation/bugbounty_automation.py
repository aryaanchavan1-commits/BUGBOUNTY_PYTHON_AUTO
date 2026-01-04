import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import argparse

# Import modules
from modules.reconnaissance import ReconnaissanceEngine
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.report_generator import ReportGenerator
from modules.bounty_tracker import BountyTracker
from utils.config import ConfigManager
from utils.logger import setup_logging

class BugBountyAutomation:
    """Main automation engine for bug bounty hunting"""
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize the automation suite"""
        self.config = ConfigManager(config_path)
        self.logger = setup_logging()
        
        # Initialize modules
        self.recon_engine = ReconnaissanceEngine(self.config)
        self.vuln_scanner = VulnerabilityScanner(self.config)
        self.report_gen = ReportGenerator(self.config)
        self.bounty_tracker = BountyTracker(self.config)
        
        self.logger.info("Bug Bounty Automation Suite initialized")
    
    async def run_full_assessment(self, target: str) -> Dict[str, Any]:
        """
        Run complete bug bounty assessment on target
        """
        self.logger.info(f"Starting full assessment for: {target}")
        start_time = time.time()
        
        # Phase 1: Reconnaissance
        self.logger.info("Phase 1: Starting reconnaissance...")
        recon_results = await self.recon_engine.run_reconnaissance(target)
        
        # Phase 2: Vulnerability Scanning
        self.logger.info("Phase 2: Starting vulnerability scanning...")
        vuln_results = await self.vuln_scanner.run_scanning(target, recon_results)
        
        # Phase 3: Report Generation
        self.logger.info("Phase 3: Generating reports...")
        report_path = self.report_gen.generate_comprehensive_report(
            target, recon_results, vuln_results
        )
        
        # Phase 4: Bounty Tracking
        self.logger.info("Phase 4: Updating bounty tracker...")
        self.bounty_tracker.update_tracker(target, vuln_results)
        
        # Calculate and log results
        duration = time.time() - start_time
        self.logger.info(f"Assessment completed in {duration:.2f} seconds")
        
        return {
            "target": target,
            "recon_results": recon_results,
            "vulnerability_results": vuln_results,
            "report_path": report_path,
            "duration": duration,
            "timestamp": datetime.now().isoformat()
        }
    
    async def run_recon_only(self, target: str) -> Dict[str, Any]:
        """Run only reconnaissance phase"""
        self.logger.info(f"Starting reconnaissance for: {target}")
        return await self.recon_engine.run_reconnaissance(target)
    
    async def run_vuln_scan_only(self, target: str, recon_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Run only vulnerability scanning phase"""
        self.logger.info(f"Starting vulnerability scanning for: {target}")
        if not recon_data:
            recon_data = await self.recon_engine.run_reconnaissance(target)
        return await self.vuln_scanner.run_scanning(target, recon_data)
    
    def generate_bounty_report(self, target: str) -> str:
        """Generate bounty-specific report"""
        return self.report_gen.generate_bounty_report(target)
    
    def get_earnings_summary(self) -> Dict[str, Any]:
        """Get summary of bug bounty earnings"""
        return self.bounty_tracker.get_earnings_summary()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Bug Bounty Automation Suite 2026")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--mode", choices=["full", "recon", "scan", "report"], 
                       default="full", help="Automation mode")
    parser.add_argument("--config", default="config.json", 
                       help="Configuration file path")
    parser.add_argument("--output", help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Initialize automation suite
    automation = BugBountyAutomation(args.config)
    
    if args.output:
        automation.config.set_output_dir(args.output)
    
    # Run appropriate mode
    if args.mode == "full":
        results = asyncio.run(automation.run_full_assessment(args.target))
        print(f"Assessment completed. Report saved to: {results['report_path']}")
        
    elif args.mode == "recon":
        results = asyncio.run(automation.run_recon_only(args.target))
        print(f"Reconnaissance completed. Found {len(results.get('subdomains', []))} subdomains")
        
    elif args.mode == "scan":
        results = asyncio.run(automation.run_vuln_scan_only(args.target))
        print(f"Vulnerability scanning completed. Found {len(results.get('vulnerabilities', []))} vulnerabilities")
        
    elif args.mode == "report":
        report_path = automation.generate_bounty_report(args.target)
        print(f"Bounty report generated: {report_path}")

if __name__ == "__main__":
    main()
