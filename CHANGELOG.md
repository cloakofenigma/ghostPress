# Changelog

All notable changes to GhostPress will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-02-12

### 🎉 Major Release - Complete Rewrite

### Added

#### Core Features
- **Enhanced Error Handling**: Comprehensive error logging with dedicated error log file
- **Configuration File Support**: Load defaults from `~/.ghostpress/config`
- **Structured Findings Database**: Organized findings with severity, impact, and mitigation
- **Multiple Report Formats**: HTML, XLSX, Markdown, and JSON reports
- **Progress Tracking**: Visual progress indicators for scan phases
- **Parallel Execution**: GNU parallel support for faster scanning
- **Dry Run Mode**: Test scanning logic without making actual requests

#### Scanning Enhancements
- **TimThumb Detection**: Identify vulnerable TimThumb installations
- **Enhanced Version Detection**: Multiple methods for WordPress version identification
- **Plugin/Theme Versioning**: Extract version numbers from source code
- **Debug Mode Detection**: Identify WP_DEBUG exposure
- **Application Passwords Check**: Test WordPress 5.6+ application passwords endpoint
- **False Positive Reduction**: Improved validation of HTTP responses
- **Extended User Enumeration**: Configurable range (default 1-20)

#### Security Improvements
- **SSL Validation**: Enhanced curl security with proper certificate validation
- **Rate Limiting**: Consistent rate limiting across all HTTP requests
- **Stealth Enhancements**: All requests now use stealth_curl function
- **Response Size Validation**: Detect suspicious response sizes
- **Backup File Detection**: Extended list of backup file extensions

#### Reporting
- **HTML Reports**: Beautiful, interactive HTML reports with:
  - Responsive design
  - Color-coded severity indicators
  - Risk score calculation
  - Executive summary with charts
  - Detailed findings with evidence

- **XLSX Reports**: Comprehensive Excel spreadsheets with:
  - Summary sheet with statistics
  - All findings sheet with filtering
  - Separate sheets per severity level
  - Color-coded cells
  - Wrapped text for readability

- **Structured Findings**: Each finding includes:
  - Title
  - Severity (Critical, High, Medium, Low, Info)
  - Category
  - Description
  - Impact assessment
  - Remediation steps
  - Evidence/proof

#### User Experience
- **Verbose Mode**: Detailed output for debugging (`-v, --verbose`)
- **Quiet Mode**: Minimal output for automation (`-q, --quiet`)
- **Progress Indicators**: Visual feedback during long scans
- **Duration Tracking**: Scan time measurement and reporting
- **Color-Coded Output**: Enhanced readability with ANSI colors
- **Better Help Text**: Improved usage documentation

#### Notifications
- **Slack Integration**: Send scan completion notifications to Slack
- **Discord Integration**: Send notifications to Discord webhooks

#### Tool Integration
- **Version Checks**: Verify tool versions during prerequisites check
- **Optional Tools**: Graceful handling of missing optional tools
- **Python Integration**: Automated HTML/XLSX report generation
- **Nuclei Optimization**: Template filtering and severity-based scanning

#### Command-Line Options
- `--max-users`: Configure user enumeration range
- `--skip-nmap`: Skip resource-intensive Nmap scans
- `--dry-run`: Preview scan without making requests
- `--verbose`: Enable detailed output
- `--quiet`: Suppress non-critical output
- `--slack-webhook`: Slack notification URL
- `--discord-webhook`: Discord notification URL
- `--install-deps`: Automated dependency installation

### Changed

#### Breaking Changes
- **Configuration Format**: New configuration file structure at `~/.ghostpress/config`
- **Output Structure**: Reorganized output directory with severity-based findings
- **Report Format**: Enhanced report structure with structured findings

#### Improvements
- **Error Handling**: All commands now have proper error handling
- **Logging**: Comprehensive logging to both console and file
- **Code Organization**: Modular function structure for better maintainability
- **Documentation**: Extensive inline comments and documentation
- **Performance**: Parallel execution where possible
- **Stealth**: Consistent stealth delays across all operations

### Fixed
- **Silent Failures**: All `|| true` commands now log errors
- **Duplicate Nmap Scripts**: Fixed duplicate script names in nmap command
- **Rate Limit Bypasses**: All HTTP requests now respect configured delays
- **False Positives**: Improved detection of custom 404 pages
- **JSON Parsing**: Better error handling for malformed JSON responses
- **File Permissions**: Proper handling of sensitive file checks
- **Directory Indexing Detection**: More accurate directory listing detection
- **SSL Errors**: Better handling of SSL/TLS errors

### Security
- **SSL Certificate Validation**: Enabled by default in curl commands
- **Sensitive File Handling**: No longer save sensitive files to disk
- **Credential Protection**: Better handling of API tokens and webhooks
- **Input Validation**: Enhanced target validation and sanitization

### Removed
- **Hardcoded Values**: Moved to configuration files
- **Unsafe Operations**: Removed commands that could cause issues
- **Legacy Code**: Cleaned up obsolete code paths

---

## [1.0.0] - 2024-01-15

### Initial Release

#### Features
- Basic passive reconnaissance (DNS, WHOIS, subdomain enumeration)
- Active scanning with WPScan and Nmap
- Configuration analysis (headers, SSL, XML-RPC)
- Basic reporting (Markdown and JSON)
- User enumeration testing
- File exposure detection

#### Tools Integrated
- WPScan
- Nmap
- Nuclei
- WhatWeb
- SSLScan
- Standard Unix utilities (curl, dig, whois)

#### Core Functionality
- Three-phase scanning approach
- Basic stealth features
- Configurable delays and threads
- Simple markdown reports

---

## Planned Features (Roadmap)

### [2.1.0] - Planned
- [ ] CVE correlation and CVSS scoring
- [ ] Historical comparison (diff with previous scans)
- [ ] Advanced filtering and search in findings
- [ ] Custom report templates
- [ ] Multi-target scanning
- [ ] Scan profiles (quick, normal, thorough)

### [2.2.0] - Planned
- [ ] Web UI for report viewing
- [ ] Database storage for scan history
- [ ] Trend analysis over time
- [ ] Compliance checks (OWASP, PCI-DSS)
- [ ] Integration with vulnerability databases

### [3.0.0] - Planned
- [ ] Plugin system for custom checks
- [ ] API for programmatic access
- [ ] Distributed scanning
- [ ] Machine learning for anomaly detection
- [ ] Enhanced stealth techniques

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute to this project.

## Support

For questions, issues, or feature requests, please visit:
- GitHub Issues: https://github.com/yourusername/ghostpress/issues
- Documentation: https://github.com/yourusername/ghostpress/wiki
