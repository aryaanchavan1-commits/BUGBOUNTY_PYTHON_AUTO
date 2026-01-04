"""
Bounty Tracker for Bug Bounty Automation
Tracks bug bounty submissions, earnings, and program information
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

class BountyTracker:
    """Track bug bounty submissions and earnings"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.data_file = config.get('bounty_data_file', 'bounty_data.json')
        
        # Initialize data structure
        self.data = self._load_data()
    
    def _load_data(self) -> Dict[str, Any]:
        """Load existing bounty data"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading bounty data: {e}")
        
        return {
            'submissions': [],
            'earnings': {
                'total': 0,
                'by_program': {},
                'by_month': {},
                'by_year': {}
            },
            'programs': {},
            'statistics': {
                'total_submissions': 0,
                'accepted_count': 0,
                'rejected_count': 0,
                'average_payout': 0,
                'success_rate': 0
            }
        }
    
    def _save_data(self):
        """Save bounty data to file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving bounty data: {e}")
    
    def update_tracker(self, target: str, vuln_results: Dict[str, Any]):
        """Update tracker with new assessment results"""
        self.logger.info(f"Updating bounty tracker for {target}")
        
        # Add submission record
        submission = {
            'target': target,
            'timestamp': time.time(),
            'date': datetime.now().isoformat(),
            'vulnerabilities_found': vuln_results.get('total_vulnerabilities', 0),
            'critical_count': vuln_results.get('critical_count', 0),
            'high_count': vuln_results.get('high_count', 0),
            'medium_count': vuln_results.get('medium_count', 0),
            'low_count': vuln_results.get('low_count', 0),
            'risk_score': vuln_results.get('risk_score', 0),
            'status': 'pending',  # pending, accepted, rejected
            'payout': 0,
            'program': self._get_program_for_target(target)
        }
        
        self.data['submissions'].append(submission)
        self.data['statistics']['total_submissions'] += 1
        
        # Update program information
        program = submission['program']
        if program not in self.data['programs']:
            self.data['programs'][program] = {
                'name': program,
                'submissions': 0,
                'accepted': 0,
                'total_payout': 0,
                'average_payout': 0
            }
        
        self.data['programs'][program]['submissions'] += 1
        
        self._save_data()
        self.logger.info(f"Tracker updated for {target}")
    
    def record_submission(self, target: str, program: str, status: str, payout: float = 0):
        """Record submission status and payout"""
        self.logger.info(f"Recording submission for {target}: {status} - ${payout}")
        
        # Find submission
        submission = None
        for sub in self.data['submissions']:
            if sub['target'] == target:
                submission = sub
                break
        
        if submission:
            submission['status'] = status
            submission['payout'] = payout
            
            # Update program statistics
            program_name = submission['program']
            if program_name in self.data['programs']:
                program_data = self.data['programs'][program_name]
                program_data['submissions'] += 1
                
                if status == 'accepted':
                    program_data['accepted'] += 1
                    program_data['total_payout'] += payout
                    program_data['average_payout'] = program_data['total_payout'] / program_data['accepted']
                
                self.data['programs'][program_name] = program_data
            
            # Update overall statistics
            if status == 'accepted':
                self.data['statistics']['accepted_count'] += 1
                self.data['earnings']['total'] += payout
            elif status == 'rejected':
                self.data['statistics']['rejected_count'] += 1
            
            # Update earnings by time period
            date = datetime.fromtimestamp(submission['timestamp'])
            month_key = f"{date.year}-{date.month:02d}"
            year_key = str(date.year)
            
            if month_key not in self.data['earnings']['by_month']:
                self.data['earnings']['by_month'][month_key] = 0
            if year_key not in self.data['earnings']['by_year']:
                self.data['earnings']['by_year'][year_key] = 0
            
            if status == 'accepted':
                self.data['earnings']['by_month'][month_key] += payout
                self.data['earnings']['by_year'][year_key] += payout
            
            # Update by program earnings
            if program_name not in self.data['earnings']['by_program']:
                self.data['earnings']['by_program'][program_name] = 0
            if status == 'accepted':
                self.data['earnings']['by_program'][program_name] += payout
            
            # Recalculate statistics
            self._update_statistics()
            
            self._save_data()
            self.logger.info(f"Submission recorded: {target} - {status} - ${payout}")
        else:
            self.logger.error(f"Submission not found for target: {target}")
    
    def _update_statistics(self):
        """Update overall statistics"""
        total = self.data['statistics']['total_submissions']
        accepted = self.data['statistics']['accepted_count']
        
        if total > 0:
            self.data['statistics']['success_rate'] = round((accepted / total) * 100, 2)
        
        if accepted > 0:
            self.data['statistics']['average_payout'] = round(
                self.data['earnings']['total'] / accepted, 2
            )
    
    def _get_program_for_target(self, target: str) -> str:
        """Get program name for target"""
        # This could be enhanced to look up programs based on target
        # For now, return a default or extract from target
        return target.split('.')[0]  # Simple extraction
    
    def get_earnings_summary(self) -> Dict[str, Any]:
        """Get comprehensive earnings summary"""
        return {
            'total_earnings': self.data['earnings']['total'],
            'by_program': self.data['earnings']['by_program'],
            'by_month': self.data['earnings']['by_month'],
            'by_year': self.data['earnings']['by_year'],
            'statistics': self.data['statistics']
        }
    
    def get_program_statistics(self, program: str) -> Dict[str, Any]:
        """Get statistics for specific program"""
        if program in self.data['programs']:
            return self.data['programs'][program]
        return {
            'name': program,
            'submissions': 0,
            'accepted': 0,
            'total_payout': 0,
            'average_payout': 0
        }
    
    def get_submission_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get submission history"""
        return sorted(
            self.data['submissions'], 
            key=lambda x: x['timestamp'], 
            reverse=True
        )[:limit]
    
    def get_pending_submissions(self) -> List[Dict[str, Any]]:
        """Get pending submissions"""
        return [s for s in self.data['submissions'] if s['status'] == 'pending']
    
    def add_program(self, program_name: str, details: Dict[str, Any]):
        """Add new program to tracker"""
        self.data['programs'][program_name] = {
            'name': program_name,
            'submissions': 0,
            'accepted': 0,
            'total_payout': 0,
            'average_payout': 0,
            **details
        }
        self._save_data()
    
    def get_top_programs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top programs by earnings"""
        programs = []
        for name, data in self.data['programs'].items():
            programs.append({
                'name': name,
                'earnings': data.get('total_payout', 0),
                'submissions': data.get('submissions', 0),
                'accepted': data.get('accepted', 0),
                'average_payout': data.get('average_payout', 0)
            })
        
        return sorted(programs, key=lambda x: x['earnings'], reverse=True)[:limit]
    
    def get_monthly_earnings(self, year: int = None) -> Dict[str, float]:
        """Get monthly earnings for a specific year"""
        if year is None:
            year = datetime.now().year
        
        monthly = {}
        for key, amount in self.data['earnings']['by_month'].items():
            if key.startswith(str(year)):
                monthly[key] = amount
        
        return monthly
    
    def export_data(self, format: str = 'json') -> str:
        """Export tracker data"""
        if format == 'json':
            filename = f"bounty_tracker_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(os.getcwd(), filename)
            
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            
            return filepath
        
        elif format == 'csv':
            import csv
            filename = f"bounty_tracker_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            filepath = os.path.join(os.getcwd(), filename)
            
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Target', 'Date', 'Program', 'Status', 'Payout', 'Vulnerabilities', 'Risk Score'])
                
                for submission in self.data['submissions']:
                    writer.writerow([
                        submission['target'],
                        submission['date'],
                        submission['program'],
                        submission['status'],
                        submission['payout'],
                        submission['vulnerabilities_found'],
                        submission['risk_score']
                    ])
            
            return filepath
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics and insights"""
        submissions = self.data['submissions']
        
        if not submissions:
            return {
                'total_submissions': 0,
                'accepted_rate': 0,
                'average_payout': 0,
                'highest_payout': 0,
                'most_productive_month': None,
                'best_program': None,
                'time_to_resolution': 0
            }
        
        # Calculate metrics
        total_submissions = len(submissions)
        accepted_submissions = [s for s in submissions if s['status'] == 'accepted']
        rejected_submissions = [s for s in submissions if s['status'] == 'rejected']
        
        accepted_rate = (len(accepted_submissions) / total_submissions) * 100 if total_submissions > 0 else 0
        average_payout = sum(s['payout'] for s in accepted_submissions) / len(accepted_submissions) if accepted_submissions else 0
        highest_payout = max(s['payout'] for s in accepted_submissions) if accepted_submissions else 0
        
        # Most productive month
        monthly_counts = {}
        for sub in accepted_submissions:
            date = datetime.fromtimestamp(sub['timestamp'])
            month = f"{date.year}-{date.month:02d}"
            monthly_counts[month] = monthly_counts.get(month, 0) + 1
        
        most_productive_month = max(monthly_counts, key=monthly_counts.get) if monthly_counts else None
        
        # Best program
        program_earnings = {}
        for sub in accepted_submissions:
            program = sub['program']
            program_earnings[program] = program_earnings.get(program, 0) + sub['payout']
        
        best_program = max(program_earnings, key=program_earnings.get) if program_earnings else None
        
        # Average time to resolution (simplified)
        time_to_resolution = 0  # Would need submission and resolution dates
        
        return {
            'total_submissions': total_submissions,
            'accepted_rate': round(accepted_rate, 2),
            'average_payout': round(average_payout, 2),
            'highest_payout': highest_payout,
            'most_productive_month': most_productive_month,
            'best_program': best_program,
            'time_to_resolution': time_to_resolution
        }
