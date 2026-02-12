# 👻 GhostPress

> **WordPress Non-Intrusive Vulnerability Assessment Tool**

GhostPress is a comprehensive, automated security assessment tool specifically designed for WordPress installations. It performs passive reconnaissance, active scanning, and configuration analysis to identify security vulnerabilities, misconfigurations, and information disclosures - all while maintaining a low profile.

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/yourusername/ghostpress)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0+-orange.svg)](https://www.gnu.org/software/bash/)

## ✨ Features

### 🔍 Comprehensive Scanning
- **Phase 1 - Passive Reconnaissance**
  - DNS enumeration and WHOIS lookup
  - Subdomain discovery via certificate transparency
  - Technology fingerprinting (WhatWeb)
  - WordPress version detection (multiple methods)
  - Plugin and theme enumeration
  - TimThumb vulnerability detection

- **Phase 2 - Active Scanning**
  - WPScan integration with API support
  - Nuclei template-based vulnerability scanning
  - Content discovery (ffuf/custom)
  - Plugin and theme vulnerability detection
  - Backup file detection

- **Phase 3 - Configuration Analysis**
  - SSL/TLS configuration review
  - Security headers analysis
  - REST API enumeration and testing
  - XML-RPC status check
  - User enumeration testing (multiple vectors)
  - File exposure detection
  - Directory indexing checks

### 📊 Advanced Reporting
- **Multiple Report Formats**
  - 📄 Markdown reports
  - 🌐 Interactive HTML reports with charts
  - 📊 Excel (XLSX) spreadsheets with filtering
  - 📋 JSON for automation/integration

- **Detailed Findings** with:
  - Issue title
  - Severity rating (Critical, High, Medium, Low, Info)
  - Description
  - Impact assessment
  - Remediation steps
  - Evidence/proof

### 🛡️ Security & Stealth
- Configurable stealth delays between requests
- Rate limiting support
- Custom User-Agent strings
- Non-intrusive scanning modes
- Respects target resources

### ⚙️ Advanced Features
- Configuration file support (`~/.ghostpress/config`)
- Parallel execution with GNU parallel
- Progress tracking and verbose modes
- Dry-run mode for testing
- Error logging and debugging
- Webhook notifications (Slack, Discord)
- Resume capability
- CVE correlation (future)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ghostpress.git
cd ghostpress

# Run installation script
chmod +x install.sh
./install.sh --install-deps --setup

# Or manually install dependencies
sudo apt-get update
sudo apt-get install -y curl dnsutils whois jq nmap sslscan whatweb parallel python3 python3-pip
sudo gem install wpscan
pip3 install openpyxl jinja2

# Make scripts executable
chmod +x ghostpress.sh generate_reports.py
```

### Basic Usage

```bash
# Simple scan
./ghostpress.sh -t example.com

# Scan with WPScan API token for vulnerability detection
./ghostpress.sh -t example.com --wpscan-api YOUR_API_TOKEN

# Verbose scan with custom output directory
./ghostpress.sh -t example.com -v -o /path/to/output

# Stealthy scan with increased delays
./ghostpress.sh -t example.com -d 5 -T 2 --skip-nmap

# Quick scan (skip passive recon)
./ghostpress.sh -t example.com --skip-phase1
```

## 📖 Usage

### Command-Line Options

```
Usage: ./ghostpress.sh -t <target> [options]

Required:
  -t, --target <domain>       Target domain (e.g., example.com)

Optional:
  -o, --output <dir>          Output directory (default: ./ghostpress-scan-TIMESTAMP)
  -c, --config <file>         Configuration file (default: ~/.ghostpress/config)
  -d, --delay <seconds>       Stealth delay between requests (default: 2)
  -r, --rate-limit <num>      Rate limit for nuclei (default: 10)
  -T, --threads <num>         Thread count for tools (default: 5)
  -w, --wordlist <file>       Custom wordlist for content discovery
  -u, --max-users <num>       Maximum user IDs to enumerate (default: 20)

Scan Control:
  --skip-phase1               Skip passive reconnaissance
  --skip-phase2               Skip active scanning
  --skip-phase3               Skip configuration analysis
  --skip-nmap                 Skip Nmap scanning
  --wpscan-api <token>        WPScan API token for vulnerability detection

Behavior:
  -v, --verbose               Verbose output
  -q, --quiet                 Quiet mode (errors only)
  --dry-run                   Dry run mode (no actual requests)

Notifications:
  --slack-webhook <url>       Slack webhook URL for notifications
  --discord-webhook <url>     Discord webhook URL for notifications

Other:
  --install-deps              Install required dependencies
  --version                   Show version information
  -h, --help                  Show help message
```

### Configuration File

Create `~/.ghostpress/config` to set default values:

```bash
# Target Configuration
TARGET="example.com"

# Scan Performance
THREADS=10
RATE_LIMIT=15
TIMEOUT=30
STEALTH_DELAY=1

# WPScan API Token
WPSCAN_API_TOKEN="your-api-token-here"

# Notifications
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

## 📊 Report Structure

GhostPress generates comprehensive reports with the following structure:

```
ghostpress-scan-20240212-143022/
├── phase1-passive/              # Passive reconnaissance results
│   ├── dns-whois-info.txt
│   ├── subdomains-crtsh.txt
│   ├── whatweb-fingerprint.json
│   ├── homepage-source.html
│   ├── wp-plugins-detected.txt
│   └── ...
├── phase2-active/               # Active scanning results
│   ├── wpscan-results.json
│   ├── nuclei-wordpress.json
│   ├── content-discovery.json
│   └── ...
├── phase3-config/               # Configuration analysis
│   ├── security-headers.txt
│   ├── sslscan-results.txt
│   ├── api-enumeration.txt
│   ├── xmlrpc-analysis.txt
│   └── ...
├── findings/                    # Findings by severity
│   ├── critical/
│   ├── high/
│   ├── medium/
│   ├── low/
│   └── info/
├── reports/                     # Generated reports
│   ├── report.md               # Markdown report
│   ├── report.html             # Interactive HTML report
│   ├── report.xlsx             # Excel spreadsheet
│   └── findings.json           # Machine-readable findings
├── ghostpress.log              # Detailed execution log
└── errors.log                  # Error log
```

## 🔧 Requirements

### Required Tools
- `curl` - HTTP client
- `dig` - DNS lookups
- `whois` - WHOIS queries
- `jq` - JSON processing

### Optional Tools (Enhanced Features)
- `nmap` - Network scanning
- `whatweb` - Technology fingerprinting
- `wpscan` - WordPress-specific scanning
- `nuclei` - Template-based vulnerability scanning
- `sslscan` - SSL/TLS analysis
- `ffuf` - Content discovery
- `parallel` - Parallel execution
- `python3` - Report generation (with `openpyxl` and `jinja2`)

### Get WPScan API Token
For enhanced vulnerability detection, get a free API token from: https://wpscan.com/api

## 🎯 Use Cases

### Security Auditing
```bash
# Comprehensive audit with all phases
./ghostpress.sh -t client-site.com --wpscan-api TOKEN -v

# Review reports
firefox ./ghostpress-scan-*/reports/report.html
```

### Penetration Testing
```bash
# Initial reconnaissance
./ghostpress.sh -t target.com --skip-phase2 -d 3

# Follow-up active scanning
./ghostpress.sh -t target.com --skip-phase1 --wpscan-api TOKEN
```

### Continuous Monitoring
```bash
# Scheduled scan with notifications
./ghostpress.sh -t monitored-site.com \
  --wpscan-api TOKEN \
  --slack-webhook "https://hooks.slack.com/..." \
  -q
```

### Bug Bounty Hunting
```bash
# Stealthy reconnaissance
./ghostpress.sh -t target.com -d 5 -T 2 --skip-nmap

# Thorough vulnerability scanning
./ghostpress.sh -t target.com --wpscan-api TOKEN -u 50
```

## 🛡️ Responsible Use

**⚠️ IMPORTANT:** This tool is designed for authorized security testing only.

- ✅ Obtain written permission before scanning
- ✅ Respect rate limits and target resources
- ✅ Follow responsible disclosure practices
- ✅ Comply with local laws and regulations
- ❌ Do NOT use for unauthorized testing
- ❌ Do NOT perform DoS or brute-force attacks
- ❌ Do NOT exploit vulnerabilities without permission

## 🐛 Troubleshooting

### Common Issues

**Missing Tools:**
```bash
./ghostpress.sh --version  # Check installed tools
./install.sh --install-deps  # Install missing dependencies
```

**Permission Errors:**
```bash
chmod +x ghostpress.sh generate_reports.py
```

**Python Module Errors:**
```bash
pip3 install --user openpyxl jinja2
```

**Nuclei Templates Missing:**
```bash
nuclei -update-templates
```

**WPScan Issues:**
```bash
gem update wpscan
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/ghostpress.git
cd ghostpress

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
./ghostpress.sh -t test-site.com --dry-run

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed version history.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **WPScan Team** - WordPress vulnerability database
- **ProjectDiscovery** - Nuclei templates
- **SecLists** - Comprehensive wordlists
- **OWASP** - Security best practices

## 📧 Contact

- **GitHub Issues:** [Report bugs or request features](https://github.com/yourusername/ghostpress/issues)
- **Security Issues:** Please report security vulnerabilities responsibly to cloakofenigma@gmail.com

## ⭐ Star History

If you find GhostPress useful, please consider giving it a star on GitHub!

---

**Disclaimer:** This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems you do not own.
