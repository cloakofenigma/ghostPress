#!/usr/bin/env python3
"""
GhostPress Batch Scanner
Orchestrates scanning of multiple domains from a list file
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class BatchScanner:
    """Main batch scanning orchestrator"""

    def __init__(self, args):
        self.args = args
        self.script_dir = Path(__file__).parent.absolute()
        self.ghostpress_script = self.script_dir / "ghostpress.sh"

        # Validate ghostpress.sh exists
        if not self.ghostpress_script.exists():
            raise FileNotFoundError(f"ghostpress.sh not found at: {self.ghostpress_script}")

        # Create timestamped batch directory
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.batch_dir = Path(args.output) / f"batch-scan-{timestamp}"
        self.batch_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.setup_logging()

        # Statistics
        self.stats = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'total_findings': 0,
            'start_time': datetime.now()
        }

        # Failed domains tracking
        self.failed_domains = []

    def setup_logging(self):
        """Setup logging to file and console"""
        log_file = self.batch_dir / "batch-scan.log"

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO if self.args.verbose else logging.WARNING)
        console_handler.setFormatter(formatter)

        # Setup logger
        self.logger = logging.getLogger('GhostPressBatch')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info(f"Batch scan initialized: {self.batch_dir}")

    def print_banner(self):
        """Print startup banner"""
        banner = f"""{Colors.CYAN}
   _____ _               _   _____
  / ____| |             | | |  __ \\
 | |  __| |__   ___  ___| |_| |__) | __ ___  ___ ___
 | | |_ | '_ \\ / _ \\/ __| __|  ___/ '__/ _ \\/ __/ __|
 | |__| | | | | (_) \\__ \\ |_| |   | | |  __/\\__ \\__ \\
  \\_____|_| |_|\\___/|___/\\__|_|   |_|  \\___||___/___/

  {Colors.BOLD}Batch Scanner v1.0{Colors.END}{Colors.CYAN}
  Sequential Multi-Domain WordPress Security Assessment
{Colors.END}"""
        print(banner)
        print(f"{Colors.BLUE}{'='*70}{Colors.END}\n")

    def parse_domain_list(self, file_path: Path) -> List[str]:
        """
        Parse domain list from text file

        Format:
        - One domain per line
        - Skip empty lines
        - Skip lines starting with # (comments)
        - Strip whitespace
        - Remove duplicates
        """
        self.logger.info(f"Reading domain list from: {file_path}")

        if not file_path.exists():
            raise FileNotFoundError(f"Domain list file not found: {file_path}")

        domains = []
        seen = set()
        line_num = 0

        with open(file_path, 'r') as f:
            for line in f:
                line_num += 1
                # Strip whitespace
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Basic validation
                domain = self.clean_domain(line)

                if not self.is_valid_domain(domain):
                    self.logger.warning(f"Line {line_num}: Invalid domain format: {line}")
                    continue

                # Check for duplicates
                if domain in seen:
                    self.logger.warning(f"Line {line_num}: Duplicate domain skipped: {domain}")
                    continue

                seen.add(domain)
                domains.append(domain)

        self.logger.info(f"Loaded {len(domains)} valid domains from {file_path}")

        if not domains:
            raise ValueError("No valid domains found in domain list file")

        return domains

    def clean_domain(self, domain: str) -> str:
        """Clean domain string (remove protocol, trailing slash, etc.)"""
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove trailing slash
        domain = domain.rstrip('/')
        # Remove port if present (we'll let ghostpress.sh handle it)
        # domain = re.sub(r':\d+$', '', domain)
        return domain

    def is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        # Very basic regex for domain validation
        # Allows: example.com, sub.example.com, example.co.uk, 192.168.1.1:8080
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(\:\d+)?$'
        return bool(re.match(pattern, domain))

    def sanitize_domain_for_directory(self, domain: str) -> str:
        """Convert domain to safe directory name"""
        # Replace special characters with underscore
        safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
        return safe_name

    def is_domain_already_scanned(self, domain: str) -> bool:
        """Check if domain was already scanned in this batch"""
        domain_dir = self.batch_dir / self.sanitize_domain_for_directory(domain)

        # Check if directory exists and has a findings.json file
        findings_file = domain_dir / "reports" / "findings.json"

        if findings_file.exists():
            # Verify it's not empty/corrupt
            try:
                with open(findings_file, 'r') as f:
                    data = json.load(f)
                    # Check if it has basic structure
                    if 'scan_metadata' in data and 'findings' in data:
                        return True
            except (json.JSONDecodeError, IOError):
                self.logger.warning(f"Corrupt findings file found for {domain}, will rescan")
                return False

        return False

    def scan_domain(self, domain: str, index: int, total: int) -> Tuple[bool, Optional[Dict]]:
        """
        Scan a single domain using ghostpress.sh

        Returns:
            (success: bool, findings_summary: Dict or None)
        """
        print(f"\n{Colors.CYAN}[{index}/{total}] {Colors.BOLD}{domain}{Colors.END}")
        self.logger.info(f"Starting scan for domain {index}/{total}: {domain}")

        # Check if already scanned (resume capability)
        if self.args.resume and self.is_domain_already_scanned(domain):
            print(f"  {Colors.YELLOW}⏭️  Already scanned (resume mode), skipping{Colors.END}")
            self.logger.info(f"Domain {domain} already scanned, skipping")
            self.stats['skipped'] += 1

            # Try to load existing findings for stats
            domain_dir = self.batch_dir / self.sanitize_domain_for_directory(domain)
            findings_file = domain_dir / "reports" / "findings.json"
            try:
                with open(findings_file, 'r') as f:
                    data = json.load(f)
                    findings_count = len(data.get('findings', []))
                    self.stats['total_findings'] += findings_count
                    print(f"  {Colors.GREEN}✓ Previously found {findings_count} findings{Colors.END}")
            except:
                pass

            return True, None

        # Create domain output directory
        domain_dir = self.batch_dir / self.sanitize_domain_for_directory(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        # Build ghostpress.sh command
        cmd = [
            str(self.ghostpress_script),
            '-t', domain,
            '-o', str(domain_dir)
        ]

        # Add optional arguments
        if self.args.wpscan_api:
            cmd.extend(['--wpscan-api', self.args.wpscan_api])

        if self.args.delay:
            cmd.extend(['-d', str(self.args.delay)])

        if self.args.threads:
            cmd.extend(['-T', str(self.args.threads)])

        if self.args.rate_limit:
            cmd.extend(['-r', str(self.args.rate_limit)])

        if self.args.verbose:
            cmd.append('-v')
        else:
            cmd.append('-q')

        if self.args.skip_nmap:
            cmd.append('--skip-nmap')

        # Add phase skip flags if specified
        if hasattr(self.args, 'skip_phase1') and self.args.skip_phase1:
            cmd.append('--skip-phase1')
        if hasattr(self.args, 'skip_phase2') and self.args.skip_phase2:
            cmd.append('--skip-phase2')
        if hasattr(self.args, 'skip_phase3') and self.args.skip_phase3:
            cmd.append('--skip-phase3')

        self.logger.debug(f"Executing command: {' '.join(cmd)}")

        # Execute scan
        try:
            start_time = datetime.now()

            result = subprocess.run(
                cmd,
                timeout=self.args.timeout,
                capture_output=not self.args.verbose,
                text=True
            )

            duration = (datetime.now() - start_time).total_seconds()
            duration_str = self.format_duration(duration)

            # Check exit code
            if result.returncode == 0:
                print(f"  {Colors.GREEN}✓ Scan completed successfully ({duration_str}){Colors.END}")
                self.logger.info(f"Domain {domain} scanned successfully in {duration_str}")

                # Load findings summary
                findings_summary = self.load_findings_summary(domain_dir)
                if findings_summary:
                    findings_count = findings_summary['count']
                    self.stats['total_findings'] += findings_count
                    print(f"  {Colors.GREEN}📊 Found {findings_count} findings{Colors.END}", end='')

                    if findings_summary['by_severity']:
                        severity_str = ', '.join([
                            f"{count} {sev}"
                            for sev, count in findings_summary['by_severity'].items()
                            if count > 0
                        ])
                        print(f" ({severity_str})")
                    else:
                        print()

                return True, findings_summary
            else:
                print(f"  {Colors.RED}✗ Scan failed with exit code {result.returncode}{Colors.END}")
                self.logger.error(f"Domain {domain} scan failed with exit code {result.returncode}")

                if result.stderr and self.args.verbose:
                    self.logger.error(f"Error output: {result.stderr}")

                return False, None

        except subprocess.TimeoutExpired:
            print(f"  {Colors.RED}✗ Scan timed out after {self.args.timeout}s{Colors.END}")
            self.logger.error(f"Domain {domain} scan timed out after {self.args.timeout}s")
            return False, None

        except Exception as e:
            print(f"  {Colors.RED}✗ Scan failed: {str(e)}{Colors.END}")
            self.logger.error(f"Domain {domain} scan failed with exception: {str(e)}")
            return False, None

    def load_findings_summary(self, domain_dir: Path) -> Optional[Dict]:
        """Load findings summary from domain scan results"""
        findings_file = domain_dir / "reports" / "findings.json"

        if not findings_file.exists():
            return None

        try:
            with open(findings_file, 'r') as f:
                data = json.load(f)

            findings = data.get('findings', [])

            # Count by severity
            by_severity = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            }

            for finding in findings:
                severity = finding.get('severity', 'INFO')
                if severity in by_severity:
                    by_severity[severity] += 1

            return {
                'count': len(findings),
                'by_severity': by_severity,
                'target': data.get('scan_metadata', {}).get('target', 'unknown')
            }

        except Exception as e:
            self.logger.warning(f"Failed to load findings summary: {e}")
            return None

    def format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def save_batch_metadata(self, domains: List[str]):
        """Save batch scan metadata"""
        metadata = {
            'start_time': self.stats['start_time'].isoformat(),
            'total_domains': len(domains),
            'domains': domains,
            'configuration': {
                'wpscan_api_enabled': bool(self.args.wpscan_api),
                'delay': self.args.delay,
                'threads': self.args.threads,
                'timeout': self.args.timeout,
                'skip_nmap': self.args.skip_nmap
            }
        }

        metadata_file = self.batch_dir / "batch-metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        # Also copy the domain list
        domain_list_copy = self.batch_dir / "domains.txt"
        with open(domain_list_copy, 'w') as f:
            f.write('\n'.join(domains))

    def save_failed_domains(self):
        """Save list of failed domains"""
        if self.failed_domains:
            failed_file = self.batch_dir / "failed-domains.txt"
            with open(failed_file, 'w') as f:
                f.write('\n'.join(self.failed_domains))
            self.logger.info(f"Failed domains saved to: {failed_file}")

    def print_summary(self):
        """Print final summary"""
        duration = (datetime.now() - self.stats['start_time']).total_seconds()
        duration_str = self.format_duration(duration)

        print(f"\n{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}📊 Batch Scan Summary{Colors.END}\n")

        print(f"  Total domains:     {self.stats['total']}")
        print(f"  {Colors.GREEN}✓ Successful:      {self.stats['successful']}{Colors.END}")

        if self.stats['skipped'] > 0:
            print(f"  {Colors.YELLOW}⏭️  Skipped:         {self.stats['skipped']} (already scanned){Colors.END}")

        if self.stats['failed'] > 0:
            print(f"  {Colors.RED}✗ Failed:          {self.stats['failed']}{Colors.END}")

        print(f"  📈 Total findings: {self.stats['total_findings']}")
        print(f"  ⏱️  Duration:       {duration_str}")

        print(f"\n{Colors.BOLD}📁 Output Directory:{Colors.END}")
        print(f"  {self.batch_dir}")

        if self.stats['failed'] > 0:
            print(f"\n{Colors.YELLOW}⚠️  Failed domains saved to:{Colors.END}")
            print(f"  {self.batch_dir / 'failed-domains.txt'}")

        print(f"\n{Colors.BLUE}{'='*70}{Colors.END}\n")

        # Log summary
        self.logger.info(f"Batch scan completed: {self.stats['successful']}/{self.stats['total']} successful")
        self.logger.info(f"Total findings: {self.stats['total_findings']}")
        self.logger.info(f"Duration: {duration_str}")

    def run(self):
        """Main execution flow"""
        try:
            # Print banner
            self.print_banner()

            # Parse domain list
            domain_list_path = Path(self.args.domain_list)
            domains = self.parse_domain_list(domain_list_path)

            print(f"{Colors.GREEN}📋 Loaded {len(domains)} domains{Colors.END}")
            print(f"{Colors.GREEN}📁 Output: {self.batch_dir}{Colors.END}\n")

            self.stats['total'] = len(domains)

            # Save metadata
            self.save_batch_metadata(domains)

            # Confirm before starting
            if not self.args.yes:
                response = input(f"{Colors.YELLOW}Start batch scan? [y/N]: {Colors.END}")
                if response.lower() not in ['y', 'yes']:
                    print("Scan cancelled.")
                    return 1

            print(f"\n{Colors.BOLD}🚀 Starting batch scan...{Colors.END}")

            # Scan each domain sequentially
            for idx, domain in enumerate(domains, 1):
                success, findings = self.scan_domain(domain, idx, len(domains))

                if success:
                    self.stats['successful'] += 1
                else:
                    self.stats['failed'] += 1
                    self.failed_domains.append(domain)

            # Save failed domains list
            self.save_failed_domains()

            # Print summary
            self.print_summary()

            # Return exit code based on results
            if self.stats['failed'] == 0:
                return 0  # All successful
            elif self.stats['successful'] > 0:
                return 2  # Partial success
            else:
                return 1  # All failed

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}⚠️  Scan interrupted by user{Colors.END}")
            self.logger.warning("Batch scan interrupted by user")
            self.save_failed_domains()
            return 130

        except Exception as e:
            print(f"\n{Colors.RED}✗ Fatal error: {str(e)}{Colors.END}")
            self.logger.error(f"Fatal error: {str(e)}", exc_info=True)
            return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='GhostPress Batch Scanner - Scan multiple WordPress sites from a list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic batch scan
  %(prog)s -l domains.txt -o /path/to/results

  # With WPScan API token
  %(prog)s -l domains.txt -o /path/to/results --wpscan-api YOUR_TOKEN

  # Resume interrupted scan
  %(prog)s -l domains.txt -o /path/to/results --resume

  # Verbose output with custom settings
  %(prog)s -l domains.txt -o /path/to/results -v -d 3 -T 10

Domain list format (domains.txt):
  example.com
  blog.example.com
  # This is a comment
  shop.example.com
        '''
    )

    # Required arguments
    parser.add_argument(
        '-l', '--domain-list',
        required=True,
        help='Path to text file containing list of domains (one per line)'
    )

    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Base output directory for batch scan results'
    )

    # GhostPress options
    parser.add_argument(
        '--wpscan-api',
        help='WPScan API token for vulnerability detection'
    )

    parser.add_argument(
        '-d', '--delay',
        type=int,
        default=2,
        help='Stealth delay between requests in seconds (default: 2)'
    )

    parser.add_argument(
        '-T', '--threads',
        type=int,
        default=5,
        help='Number of threads for scanning tools (default: 5)'
    )

    parser.add_argument(
        '-r', '--rate-limit',
        type=int,
        default=10,
        help='Rate limit for nuclei (default: 10)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=3600,
        help='Timeout per domain in seconds (default: 3600 = 1 hour)'
    )

    parser.add_argument(
        '--skip-nmap',
        action='store_true',
        help='Skip Nmap scanning'
    )

    # Batch options
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume previous scan (skip already completed domains)'
    )

    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='GhostPress Batch Scanner v1.0'
    )

    args = parser.parse_args()

    # Create and run scanner
    try:
        scanner = BatchScanner(args)
        exit_code = scanner.run()
        sys.exit(exit_code)
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.END}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
