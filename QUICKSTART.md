# GhostPress Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies

```bash
# Option A: Automated installation
./install.sh --install-deps --setup

# Option B: Manual installation (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y curl dnsutils whois jq nmap sslscan whatweb parallel python3 python3-pip
sudo gem install wpscan
pip3 install openpyxl jinja2

# Install Nuclei
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*_linux_amd64.zip
unzip nuclei_*_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
nuclei -update-templates
```

### Step 2: Configure (Optional)

```bash
# Copy example config
mkdir -p ~/.ghostpress
cp config.example ~/.ghostpress/config

# Edit configuration
nano ~/.ghostpress/config

# Add your WPScan API token (get free token at https://wpscan.com/api)
WPSCAN_API_TOKEN="your-token-here"
```

### Step 3: Run Your First Scan

```bash
# Basic scan
./ghostpress.sh -t example.com

# Scan with API token for vulnerability detection
./ghostpress.sh -t example.com --wpscan-api YOUR_TOKEN

# Verbose scan
./ghostpress.sh -t example.com -v
```

---

## 📊 View Results

After the scan completes, open the reports:

```bash
# Open HTML report in browser
firefox ./ghostpress-scan-*/reports/report.html

# View Markdown report
cat ./ghostpress-scan-*/reports/report.md

# Open Excel report
libreoffice ./ghostpress-scan-*/reports/report.xlsx
```

---

## 🎯 Common Usage Scenarios

### Security Audit

```bash
# Comprehensive audit with all features
./ghostpress.sh -t client-site.com \
  --wpscan-api YOUR_TOKEN \
  -v \
  -o /path/to/audit-results
```

### Stealth Reconnaissance

```bash
# Slow and stealthy scan
./ghostpress.sh -t target.com \
  -d 5 \
  -T 2 \
  --skip-nmap \
  -q
```

### Quick Check

```bash
# Fast scan without passive recon
./ghostpress.sh -t site.com --skip-phase1
```

### Continuous Monitoring

```bash
# Automated scan with notifications
./ghostpress.sh -t monitored-site.com \
  --wpscan-api YOUR_TOKEN \
  --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK" \
  -q
```

### Testing (No Real Requests)

```bash
# Dry run to test configuration
./ghostpress.sh -t example.com --dry-run -v
```

---

## 📋 Report Structure

Each scan creates a timestamped directory with:

```
ghostpress-scan-20240212-143022/
├── reports/
│   ├── report.html          ← Open this in browser
│   ├── report.xlsx          ← Excel spreadsheet
│   ├── report.md            ← Markdown report
│   └── findings.json        ← Machine-readable
├── phase1-passive/          ← Recon data
├── phase2-active/           ← Scan results
├── phase3-config/           ← Config analysis
├── findings/                ← By severity
└── ghostpress.log           ← Execution log
```

---

## 🔍 Understanding Report Severity

| Severity | Risk | Action Required |
|----------|------|-----------------|
| 🔴 **CRITICAL** | Immediate compromise possible | Fix immediately |
| 🟠 **HIGH** | Likely exploitable | Fix within 24-48 hours |
| 🟡 **MEDIUM** | May be exploitable | Fix within 1 week |
| 🔵 **LOW** | Minor security concern | Fix during maintenance |
| ⚪ **INFO** | Informational only | Review and consider |

---

## ⚙️ Configuration Tips

### Stealth Settings

```bash
# In ~/.ghostpress/config
STEALTH_DELAY=5          # 5 seconds between requests
THREADS=2                # Reduce concurrent connections
RATE_LIMIT=5             # Limit Nuclei requests
```

### Performance Settings

```bash
# In ~/.ghostpress/config
STEALTH_DELAY=1          # Fast scanning
THREADS=10               # More concurrent connections
RATE_LIMIT=20            # Higher Nuclei rate
```

### Notification Setup

```bash
# Slack webhook
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Discord webhook
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

---

## 🛠️ Troubleshooting

### Check Tool Installation

```bash
./ghostpress.sh --version
```

### Permission Issues

```bash
chmod +x ghostpress.sh generate_reports.py install.sh
```

### Missing Python Modules

```bash
pip3 install --user openpyxl jinja2
```

### WPScan Issues

```bash
# Update WPScan
gem update wpscan

# Update WPScan database
wpscan --update
```

### Nuclei Template Issues

```bash
nuclei -update-templates
```

---

## 💡 Pro Tips

1. **Get a WPScan API Token**
   - Free tier: https://wpscan.com/api
   - Enables vulnerability detection

2. **Use Configuration Files**
   - Save common settings to `~/.ghostpress/config`
   - No need to type same options repeatedly

3. **Review All Severity Levels**
   - Even "Info" findings can indicate security issues
   - Look for patterns across multiple low-severity findings

4. **Schedule Regular Scans**
   - Use cron for automated monitoring
   - Example: `0 2 * * 0 /path/to/ghostpress.sh -t site.com`

5. **Compare Scan Results**
   - Keep JSON reports for comparison
   - Track changes over time

6. **Use Dry Run First**
   - Test on new targets with `--dry-run`
   - Verify configuration before real scan

7. **Adjust Stealth Based on Target**
   - Internal sites: Fast settings
   - External sites: Stealth settings
   - Sensitive targets: Maximum stealth

---

## 📞 Getting Help

- **Documentation**: See `README.md` for full details
- **Examples**: Check `IMPROVEMENTS.md` for usage examples
- **Issues**: Report bugs at GitHub (when published)
- **Updates**: Check `CHANGELOG.md` for new features

---

## ⚠️ Legal Notice

**Always obtain written authorization before scanning!**

This tool is for authorized security testing only:
- ✅ Your own websites
- ✅ Client sites with written permission
- ✅ Bug bounty programs (follow scope)
- ✅ Training/lab environments
- ❌ Unauthorized scanning is illegal

---

## 🎓 Next Steps

1. Read the full documentation: `README.md`
2. Review example configurations: `config.example`
3. Understand the improvements: `IMPROVEMENTS.md`
4. Check version history: `CHANGELOG.md`
5. Run your first scan!

**Happy Hunting! 🎯**
