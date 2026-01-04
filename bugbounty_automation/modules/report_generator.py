"""
Report Generator for Bug Bounty Automation
Generates comprehensive reports and documentation
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Template
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.colors import *
from reportlab.lib.units import inch

class ReportGenerator:
    """Generate comprehensive bug bounty reports"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.output_dir = config.get('output_dir', 'reports')
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_comprehensive_report(self, target: str, recon_results: Dict[str, Any], 
                                    vuln_results: Dict[str, Any]) -> str:
        """Generate comprehensive assessment report"""
        self.logger.info(f"Generating comprehensive report for {target}")
        
        # Create report data structure
        report_data = {
            'target': target,
            'assessment_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reconnaissance': recon_results,
            'vulnerabilities': vuln_results,
            'summary': self._generate_summary(recon_results, vuln_results),
            'recommendations': self._generate_recommendations(vuln_results)
        }
        
        # Generate different report formats
        pdf_path = self._generate_pdf_report(target, report_data)
        html_path = self._generate_html_report(target, report_data)
        json_path = self._generate_json_report(target, report_data)
        
        self.logger.info(f"Reports generated: {pdf_path}, {html_path}, {json_path}")
        return pdf_path
    
    def generate_bounty_report(self, target: str) -> str:
        """Generate bug bounty specific report for submission"""
        self.logger.info(f"Generating bug bounty report for {target}")
        
        # Load previous assessment results
        results_file = os.path.join(self.output_dir, f"{target}_results.json")
        if not os.path.exists(results_file):
            self.logger.error(f"No assessment results found for {target}")
            return ""
        
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        # Generate bounty report
        bounty_data = {
            'target': target,
            'submission_date': datetime.now().strftime('%Y-%m-%d'),
            'vulnerabilities': results.get('vulnerability_results', {}),
            'critical_vulns': self._filter_critical_vulns(results.get('vulnerability_results', {})),
            'exploitation_details': self._generate_exploitation_details(results.get('vulnerability_results', {}))
        }
        
        return self._generate_bounty_submission(target, bounty_data)
    
    def _generate_summary(self, recon_results: Dict[str, Any], vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate assessment summary"""
        return {
            'total_subdomains': len(recon_results.get('subdomains', [])),
            'open_ports': len(recon_results.get('open_ports', [])),
            'total_vulnerabilities': vuln_results.get('total_vulnerabilities', 0),
            'critical_count': vuln_results.get('critical_count', 0),
            'high_count': vuln_results.get('high_count', 0),
            'medium_count': vuln_results.get('medium_count', 0),
            'low_count': vuln_results.get('low_count', 0),
            'risk_score': vuln_results.get('risk_score', 0),
            'assessment_duration': vuln_results.get('duration', 0)
        }
    
    def _generate_recommendations(self, vuln_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        recommendations = []
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate recommendations for each vulnerability type
        for vuln_type, vulns in vuln_types.items():
            severity = max([v.get('severity', 'low') for v in vulns])
            count = len(vulns)
            
            recommendations.append({
                'vulnerability_type': vuln_type,
                'severity': severity,
                'count': count,
                'recommendation': self._get_recommendation_for_type(vuln_type, severity),
                'implementation': self._get_implementation_guidance(vuln_type, severity)
            })
        
        return recommendations
    
    def _get_recommendation_for_type(self, vuln_type: str, severity: str) -> str:
        """Get recommendation text for vulnerability type"""
        recommendations = {
            'SQL Injection': {
                'critical': 'Implement parameterized queries and input validation to prevent SQL injection attacks.',
                'high': 'Use prepared statements and proper input sanitization.',
                'medium': 'Review and update input validation mechanisms.',
                'low': 'Consider additional input validation for user inputs.'
            },
            'Cross-Site Scripting (XSS)': {
                'critical': 'Implement proper output encoding and input validation to prevent XSS attacks.',
                'high': 'Use content security policy and output encoding.',
                'medium': 'Review and update output encoding mechanisms.',
                'low': 'Consider additional output encoding for user content.'
            },
            'Cross-Site Request Forgery (CSRF)': {
                'critical': 'Implement CSRF tokens for all state-changing operations.',
                'high': 'Add CSRF protection to forms and API endpoints.',
                'medium': 'Review CSRF protection implementation.',
                'low': 'Consider additional CSRF protection measures.'
            },
            'Command Injection': {
                'critical': 'Avoid using system commands with user input. Use safe APIs.',
                'high': 'Implement input validation and avoid shell command execution.',
                'medium': 'Review command execution mechanisms.',
                'low': 'Consider additional input validation.'
            },
            'Path Traversal': {
                'critical': 'Implement proper path validation and file access controls.',
                'high': 'Use whitelist-based path validation.',
                'medium': 'Review file access controls.',
                'low': 'Consider additional path validation.'
            },
            'Server-Side Request Forgery (SSRF)': {
                'critical': 'Implement URL validation and restrict internal network access.',
                'high': 'Use allowlists for allowed domains and protocols.',
                'medium': 'Review URL validation mechanisms.',
                'low': 'Consider additional URL validation.'
            }
        }
        
        return recommendations.get(vuln_type, {}).get(severity, 'Review and implement appropriate security measures.')
    
    def _get_implementation_guidance(self, vuln_type: str, severity: str) -> str:
        """Get implementation guidance for vulnerability type"""
        guidance = {
            'SQL Injection': 'Use parameterized queries, stored procedures, and ORM frameworks that handle parameterization automatically.',
            'Cross-Site Scripting (XSS)': 'Implement output encoding based on context (HTML, JavaScript, CSS, URL). Use Content Security Policy headers.',
            'Cross-Site Request Forgery (CSRF)': 'Generate unique CSRF tokens per session and validate them on all state-changing requests.',
            'Command Injection': 'Avoid using shell commands with user input. Use safe APIs and libraries for system operations.',
            'Path Traversal': 'Use whitelist-based path validation. Avoid using user input directly in file paths.',
            'Server-Side Request Forgery (SSRF)': 'Validate and sanitize URLs. Use allowlists for allowed domains and restrict access to internal networks.'
        }
        
        return guidance.get(vuln_type, 'Follow security best practices for the specific vulnerability type.')
    
    def _generate_pdf_report(self, target: str, report_data: Dict[str, Any]) -> str:
        """Generate PDF report"""
        filename = f"{target}_assessment_report.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph(f"Bug Bounty Assessment Report - {target}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Assessment Information
        assessment_info = [
            ['Target', target],
            ['Assessment Date', report_data['assessment_date']],
            ['Total Vulnerabilities', str(report_data['summary']['total_vulnerabilities'])],
            ['Risk Score', str(report_data['summary']['risk_score'])]
        ]
        
        t = Table(assessment_info, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), beige),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        story.append(t)
        story.append(Spacer(1, 12))
        
        # Vulnerability Summary
        vuln_summary = report_data['summary']
        summary_text = f"""
        <b>Vulnerability Summary:</b><br/>
        Critical: {vuln_summary['critical_count']}<br/>
        High: {vuln_summary['high_count']}<br/>
        Medium: {vuln_summary['medium_count']}<br/>
        Low: {vuln_summary['low_count']}<br/>
        Total: {vuln_summary['total_vulnerabilities']}
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Critical Vulnerabilities
        critical_vulns = [v for v in report_data['vulnerabilities']['vulnerabilities'] 
                         if v['severity'] == 'critical']
        
        if critical_vulns:
            story.append(Paragraph("<b>Critical Vulnerabilities:</b>", styles['Heading2']))
            for vuln in critical_vulns:
                vuln_text = f"""
                <b>{vuln['type']}</b><br/>
                URL: {vuln.get('url', 'N/A')}<br/>
                Description: {vuln['description']}<br/>
                Proof of Concept: {vuln['proof_of_concept']}<br/><br/>
                """
                story.append(Paragraph(vuln_text, styles['Normal']))
        
        # Recommendations
        story.append(Paragraph("<b>Security Recommendations:</b>", styles['Heading2']))
        for rec in report_data['recommendations']:
            rec_text = f"""
            <b>{rec['vulnerability_type']} ({rec['severity'].upper()})</b><br/>
            Recommendation: {rec['recommendation']}<br/>
            Implementation: {rec['implementation']}<br/><br/>
            """
            story.append(Paragraph(rec_text, styles['Normal']))
        
        doc.build(story)
        return filepath
    
    def _generate_html_report(self, target: str, report_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        filename = f"{target}_assessment_report.html"
        filepath = os.path.join(self.output_dir, filename)
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Bounty Assessment Report - {{ target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
                .summary { background-color: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; }
                .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .critical { border-left: 5px solid #dc3545; }
                .high { border-left: 5px solid #fd7e14; }
                .medium { border-left: 5px solid #ffc107; }
                .low { border-left: 5px solid #28a745; }
                .recommendation { background-color: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Bug Bounty Assessment Report</h1>
                <h2>Target: {{ target }}</h2>
                <p><strong>Assessment Date:</strong> {{ assessment_date }}</p>
            </div>
            
            <div class="summary">
                <h3>Assessment Summary</h3>
                <p><strong>Total Vulnerabilities:</strong> {{ summary.total_vulnerabilities }}</p>
                <p><strong>Risk Score:</strong> {{ summary.risk_score }}</p>
                <p><strong>Critical:</strong> {{ summary.critical_count }} | 
                   <strong>High:</strong> {{ summary.high_count }} | 
                   <strong>Medium:</strong> {{ summary.medium_count }} | 
                   <strong>Low:</strong> {{ summary.low_count }}</p>
            </div>
            
            <h3>Critical Vulnerabilities</h3>
            {% for vuln in vulnerabilities.vulnerabilities if vuln.severity == 'critical' %}
            <div class="vulnerability critical">
                <h4>{{ vuln.type }}</h4>
                <p><strong>URL:</strong> {{ vuln.url or 'N/A' }}</p>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                <p><strong>Proof of Concept:</strong> {{ vuln.proof_of_concept }}</p>
            </div>
            {% endfor %}
            
            <h3>Security Recommendations</h3>
            {% for rec in recommendations %}
            <div class="recommendation">
                <h4>{{ rec.vulnerability_type }} ({{ rec.severity.upper() }})</h4>
                <p><strong>Recommendation:</strong> {{ rec.recommendation }}</p>
                <p><strong>Implementation:</strong> {{ rec.implementation }}</p>
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(**report_data)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_json_report(self, target: str, report_data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        filename = f"{target}_assessment_report.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return filepath
    
    def _filter_critical_vulns(self, vuln_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter critical vulnerabilities for bounty submission"""
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        return [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]
    
    def _generate_exploitation_details(self, vuln_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate exploitation details for bounty submission"""
        critical_vulns = self._filter_critical_vulns(vuln_results)
        exploitation_details = []
        
        for vuln in critical_vulns:
            exploitation_details.append({
                'vulnerability_type': vuln['type'],
                'severity': vuln['severity'],
                'exploitation_steps': self._get_exploitation_steps(vuln['type']),
                'impact': self._get_vulnerability_impact(vuln['type'], vuln['severity']),
                'proof_of_concept': vuln['proof_of_concept']
            })
        
        return exploitation_details
    
    def _get_exploitation_steps(self, vuln_type: str) -> List[str]:
        """Get exploitation steps for vulnerability type"""
        steps = {
            'SQL Injection': [
                'Identify vulnerable parameter',
                'Test with SQL injection payloads',
                'Extract database information',
                'Escalate privileges if possible'
            ],
            'Cross-Site Scripting (XSS)': [
                'Identify vulnerable input field',
                'Test with XSS payloads',
                'Verify payload execution',
                'Test for session hijacking'
            ],
            'Command Injection': [
                'Identify command execution point',
                'Test with command injection payloads',
                'Verify command execution',
                'Escalate to system access'
            ]
        }
        
        return steps.get(vuln_type, ['Standard exploitation steps for this vulnerability type'])
    
    def _get_vulnerability_impact(self, vuln_type: str, severity: str) -> str:
        """Get vulnerability impact description"""
        impacts = {
            'SQL Injection': {
                'critical': 'Complete database compromise, data theft, privilege escalation',
                'high': 'Partial database access, sensitive data exposure'
            },
            'Cross-Site Scripting (XSS)': {
                'critical': 'Session hijacking, credential theft, malicious actions',
                'high': 'Session manipulation, information disclosure'
            },
            'Command Injection': {
                'critical': 'Complete system compromise, data theft, lateral movement',
                'high': 'Partial system access, file system access'
            }
        }
        
        return impacts.get(vuln_type, {}).get(severity, 'Standard impact for this vulnerability type')
    
    def _generate_bounty_submission(self, target: str, bounty_data: Dict[str, Any]) -> str:
        """Generate bug bounty submission report"""
        filename = f"{target}_bounty_submission.html"
        filepath = os.path.join(self.output_dir, filename)
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Bounty Submission - {{ target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .vulnerability { border: 1px solid #dee2e6; margin: 20px 0; padding: 20px; border-radius: 5px; }
                .critical { border-left: 5px solid #dc3545; }
                .high { border-left: 5px solid #fd7e14; }
                .section { margin: 15px 0; }
                .code { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Bug Bounty Submission</h1>
                <h2>Target: {{ target }}</h2>
                <p><strong>Submission Date:</strong> {{ submission_date }}</p>
                <p><strong>Critical Vulnerabilities:</strong> {{ critical_vulns|length }}</p>
            </div>
            
            {% for vuln in critical_vulns %}
            <div class="vulnerability {% if vuln.severity == 'critical' %}critical{% else %}high{% endif %}">
                <h3>{{ vuln.type }} ({{ vuln.severity.upper() }})</h3>
                
                <div class="section">
                    <h4>Impact</h4>
                    <p>{{ exploitation_details[loop.index0].impact }}</p>
                </div>
                
                <div class="section">
                    <h4>Proof of Concept</h4>
                    <div class="code">{{ vuln.proof_of_concept }}</div>
                </div>
                
                <div class="section">
                    <h4>Exploitation Steps</h4>
                    <ol>
                    {% for step in exploitation_details[loop.index0].exploitation_steps %}
                        <li>{{ step }}</li>
                    {% endfor %}
                    </ol>
                </div>
                
                <div class="section">
                    <h4>Technical Details</h4>
                    <p><strong>URL:</strong> {{ vuln.url or 'N/A' }}</p>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                </div>
            </div>
            {% endfor %}
            
            <div class="section">
                <h3>Recommendations</h3>
                <p>Implement proper input validation, output encoding, and security controls to prevent these vulnerabilities. Consider implementing a comprehensive security testing program.</p>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(**bounty_data)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
