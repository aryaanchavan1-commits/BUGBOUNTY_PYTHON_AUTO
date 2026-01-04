"""
Logging utilities for Bug Bounty Automation
Provides structured logging with different levels and output formats
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for console"""
    
    COLORS = {
        'DEBUG': '\033[94m',    # Blue
        'INFO': '\033[92m',     # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[91m\033[1m',  # Bold Red
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname_colored = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None, 
                 console_output: bool = True) -> logging.Logger:
    """
    Set up logging configuration for the application
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
        console_output: Whether to output logs to console
    
    Returns:
        Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger('bugbounty_automation')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname_colored)s - %(message)s'
    )
    
    # Console handler with colored output
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(ColoredFormatter(
            '%(levelname_colored)s - %(message)s'
        ))
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    
    # Prevent duplicate logs
    logger.propagate = False
    
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance
    
    Args:
        name: Optional name for the logger (will be appended to main logger name)
    
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f'bugbounty_automation.{name}')
    return logging.getLogger('bugbounty_automation')

class SecurityLogger:
    """Specialized logger for security-related events"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_vulnerability(self, vulnerability_type: str, target: str, 
                         severity: str, details: str):
        """Log discovered vulnerability"""
        self.logger.critical(
            f"VULNERABILITY DISCOVERED - Type: {vulnerability_type}, "
            f"Target: {target}, Severity: {severity}, Details: {details}"
        )
    
    def log_reconnaissance(self, target: str, findings: dict):
        """Log reconnaissance findings"""
        self.logger.info(
            f"RECONNAISSANCE COMPLETED - Target: {target}, "
            f"Findings: {findings}"
        )
    
    def log_bounty_submission(self, target: str, program: str, 
                            vulnerability_count: int, estimated_payout: float):
        """Log bounty submission"""
        self.logger.info(
            f"BOUNTY SUBMISSION - Target: {target}, Program: {program}, "
            f"Vulnerabilities: {vulnerability_count}, "
            f"Estimated Payout: ${estimated_payout}"
        )
    
    def log_automation_error(self, error_type: str, error_message: str, 
                           context: str = ""):
        """Log automation system errors"""
        self.logger.error(
            f"AUTOMATION ERROR - Type: {error_type}, "
            f"Message: {error_message}, Context: {context}"
        )

class PerformanceLogger:
    """Logger for performance metrics and timing"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.start_times = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation"""
        self.start_times[operation] = datetime.now()
        self.logger.debug(f"Started timing: {operation}")
    
    def end_timer(self, operation: str) -> float:
        """End timing and log duration"""
        if operation in self.start_times:
            duration = (datetime.now() - self.start_times[operation]).total_seconds()
            self.logger.info(f"Operation completed: {operation} - Duration: {duration:.2f}s")
            del self.start_times[operation]
            return duration
        else:
            self.logger.warning(f"No start time found for operation: {operation}")
            return 0.0
    
    def log_memory_usage(self, operation: str, memory_mb: float):
        """Log memory usage for an operation"""
        self.logger.debug(f"Memory usage - {operation}: {memory_mb:.2f} MB")
    
    def log_performance_metrics(self, metrics: dict):
        """Log performance metrics"""
        self.logger.info(f"Performance metrics: {metrics}")

def create_log_directory(log_dir: str = "logs"):
    """Create log directory if it doesn't exist"""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    return log_dir

def get_log_filename(prefix: str = "bugbounty", extension: str = "log") -> str:
    """Generate log filename with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"

def setup_module_logger(module_name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Set up a logger for a specific module
    
    Args:
        module_name: Name of the module
        log_level: Logging level for this module
    
    Returns:
        Configured logger for the module
    """
    logger = logging.getLogger(f'bugbounty_automation.{module_name}')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Add console handler if not already present
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColoredFormatter(
            '%(name)s - %(levelname_colored)s - %(message)s'
        ))
        logger.addHandler(handler)
    
    return logger

# Global logger instances
main_logger = None
security_logger = None
performance_logger = None

def initialize_global_loggers(log_level: str = "INFO", log_file: Optional[str] = None):
    """Initialize global logger instances"""
    global main_logger, security_logger, performance_logger
    
    main_logger = setup_logging(log_level, log_file)
    security_logger = SecurityLogger(main_logger)
    performance_logger = PerformanceLogger(main_logger)
    
    return main_logger, security_logger, performance_logger

def get_global_loggers():
    """Get global logger instances"""
    global main_logger, security_logger, performance_logger
    return main_logger, security_logger, performance_logger
