# GhostPress Batch Scanner

Scan multiple WordPress domains from a text file, one after another, with automatic resume capability.

## 🚀 Quick Start

### 1. Create Your Domain List

Create a text file with one domain per line:

```bash
# domains.txt
example.com
blog.example.com
shop.example.com
```

### 2. Run Batch Scan

```bash
./ghostpress_batch.py -l domains.txt -o /path/to/results
```

## 📋 Features

✅ **Sequential Scanning** - Scans domains one by one (not parallel)
✅ **Resume Capability** - Skip already-scanned domains with `--resume`
✅ **Progress Tracking** - Shows current domain and progress
✅ **Error Handling** - Continues scanning even if some domains fail
✅ **Per-Domain Reports** - Each domain gets its own directory with full reports
✅ **Batch Summary** - Overall statistics and failed domains list
✅ **Flexible Configuration** - Pass through all GhostPress options

## 📖 Usage

### Basic Command

```bash
./ghostpress_batch.py -l domains.txt -o /path/to/results
```

### With WPScan API Token

```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  --wpscan-api YOUR_API_TOKEN
```

### Resume Interrupted Scan

```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  --resume
```

### Custom Scan Settings

```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  --wpscan-api YOUR_TOKEN \
  -d 3 \              # 3 second delay between requests
  -T 10 \             # 10 threads
  --timeout 7200 \    # 2 hour timeout per domain
  -v                  # Verbose output
```

### Skip Confirmation Prompt

```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  -y                  # Auto-confirm
```

## 📝 Command-Line Options

### Required Arguments

| Option | Description |
|--------|-------------|
| `-l`, `--domain-list FILE` | Path to domain list file |
| `-o`, `--output DIR` | Base output directory |

### GhostPress Options

| Option | Default | Description |
|--------|---------|-------------|
| `--wpscan-api TOKEN` | - | WPScan API token |
| `-d`, `--delay SECS` | 2 | Stealth delay between requests |
| `-T`, `--threads NUM` | 5 | Number of threads |
| `-r`, `--rate-limit NUM` | 10 | Nuclei rate limit |
| `--timeout SECS` | 3600 | Timeout per domain (1 hour) |
| `--skip-nmap` | - | Skip Nmap scanning |

### Batch Options

| Option | Description |
|--------|-------------|
| `--resume` | Skip already-scanned domains |
| `-y`, `--yes` | Skip confirmation prompt |
| `-v`, `--verbose` | Verbose output |
| `--version` | Show version |
| `-h`, `--help` | Show help message |

## 📁 Output Structure

```
/path/to/results/
└── batch-scan-20260212-143022/
    ├── domains.txt                      # Copy of input file
    ├── batch-scan.log                   # Detailed log
    ├── batch-metadata.json              # Scan configuration
    ├── failed-domains.txt               # List of failed scans
    │
    ├── example.com/                     # Per-domain results
    │   ├── phase1-passive/
    │   ├── phase2-active/
    │   ├── phase3-config/
    │   ├── reports/
    │   │   ├── report.html
    │   │   ├── report.md
    │   │   ├── report.xlsx
    │   │   └── findings.json
    │   ├── ghostpress.log
    │   └── errors.log
    │
    ├── blog.example.com/
    │   └── (same structure)
    │
    └── shop.example.com/
        └── (same structure)
```

## 📄 Domain List Format

### Basic Format
```text
example.com
blog.example.com
shop.example.com
```

### With Comments
```text
# Production sites
example.com
blog.example.com

# Staging sites
staging.example.com

# Skip this one for now
# broken-site.com
```

### Validation Rules

✅ **Accepted formats:**
- `example.com`
- `sub.example.com`
- `example.co.uk`
- `192.168.1.1`
- `example.com:8080`

❌ **Invalid formats:**
- Empty lines (skipped automatically)
- Lines starting with `#` (comments, skipped)
- Malformed domains (logged as warning, skipped)
- Duplicate domains (logged as warning, skipped)

## 🔄 Resume Capability

The `--resume` flag is useful when:
- A scan was interrupted (Ctrl+C, timeout, system crash)
- You want to add more domains and scan only the new ones
- A few domains failed and you've fixed the issues

### How It Works

1. Checks if domain directory exists: `/path/to/results/batch-scan-XXX/domain.com/`
2. Verifies `findings.json` exists and is valid
3. If both conditions met, skips the domain
4. Otherwise, rescans the domain

### Example: Resume After Interruption

```bash
# Start scan
./ghostpress_batch.py -l domains.txt -o /tmp/results

# Press Ctrl+C after 5 domains...
# Later, resume from where you left off:

./ghostpress_batch.py -l domains.txt -o /tmp/results --resume
```

**Output:**
```
[1/10] example.com
  ⏭️  Already scanned (resume mode), skipping
  ✓ Previously found 8 findings

[2/10] blog.example.com
  ⏭️  Already scanned (resume mode), skipping
  ✓ Previously found 12 findings

[3/10] shop.example.com
  🚀 Starting scan...
  ✓ Phase 1 complete (2m 15s)
  ...
```

## 📊 Example Output

### During Scan

```
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |__) | __ ___  ___ ___
 | | |_ | '_ \ / _ \/ __| __|  ___/ '__/ _ \/ __/ __|
 | |__| | | | | (_) \__ \ |_| |   | | |  __/\__ \__ \
  \_____|_| |_|\___/|___/\__|_|   |_|  \___||___/___/

  Batch Scanner v1.0
  Sequential Multi-Domain WordPress Security Assessment
======================================================================

📋 Loaded 15 domains
📁 Output: /tmp/results/batch-scan-20260212-143022

Start batch scan? [y/N]: y

🚀 Starting batch scan...

[1/15] example.com
  ✓ Scan completed successfully (11m 23s)
  📊 Found 8 findings (1 HIGH, 3 MEDIUM, 4 LOW)

[2/15] blog.example.com
  ✓ Scan completed successfully (9m 45s)
  📊 Found 12 findings (2 HIGH, 5 MEDIUM, 5 LOW)

[3/15] broken-site.com
  ✗ Scan failed with exit code 1

[4/15] shop.example.com
  ✓ Scan completed successfully (10m 12s)
  📊 Found 6 findings (1 MEDIUM, 5 LOW)

...
```

### Final Summary

```
======================================================================
📊 Batch Scan Summary

  Total domains:     15
  ✓ Successful:      13
  ✗ Failed:          2
  📈 Total findings: 127
  ⏱️  Duration:       2h 15m

📁 Output Directory:
  /tmp/results/batch-scan-20260212-143022

⚠️  Failed domains saved to:
  /tmp/results/batch-scan-20260212-143022/failed-domains.txt

======================================================================
```

## 🔧 Troubleshooting

### Script Not Found Error

```bash
# Make script executable
chmod +x ghostpress_batch.py

# Verify ghostpress.sh exists
ls -la ghostpress.sh
```

### Permission Denied

```bash
# Check permissions
ls -la ghostpress_batch.py ghostpress.sh

# Make both executable
chmod +x ghostpress_batch.py ghostpress.sh
```

### No Domains Loaded

Check your domain list file:
```bash
# View file
cat domains.txt

# Check for valid domains
grep -v '^#' domains.txt | grep -v '^$'
```

### Domain Keeps Getting Rescanned

If `--resume` doesn't skip a domain:
1. Check if `findings.json` exists and is valid
2. The file may be corrupted - delete the domain directory to rescan

```bash
# Check findings file
cat /path/to/results/batch-scan-XXX/domain.com/reports/findings.json

# Force rescan by removing directory
rm -rf /path/to/results/batch-scan-XXX/domain.com
```

### Timeout Issues

Increase timeout for slow sites:
```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  --timeout 7200  # 2 hours
```

## 💡 Best Practices

### 1. Test First
Always test with a small domain list first:
```bash
# Create test list
echo "example.com" > test-domains.txt

# Test scan
./ghostpress_batch.py -l test-domains.txt -o /tmp/test -v
```

### 2. Use WPScan API Token
Get better vulnerability detection:
```bash
# Get free token: https://wpscan.com/api
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  --wpscan-api YOUR_TOKEN
```

### 3. Monitor Progress
Use `--verbose` for detailed output:
```bash
./ghostpress_batch.py -l domains.txt -o /path/to/results -v
```

### 4. Check Logs
Monitor the batch log in real-time:
```bash
# In another terminal
tail -f /path/to/results/batch-scan-XXX/batch-scan.log
```

### 5. Resume Long Scans
For large domain lists, use `--resume`:
```bash
# Can be interrupted and resumed multiple times
./ghostpress_batch.py -l domains.txt -o /path/to/results --resume
```

### 6. Adjust Stealth Settings
For sensitive targets, increase delays:
```bash
./ghostpress_batch.py \
  -l domains.txt \
  -o /path/to/results \
  -d 5 \           # 5 second delay
  -T 2 \           # Only 2 threads
  --skip-nmap      # Skip Nmap
```

## 🎯 Use Cases

### Security Audit (Multiple Clients)
```bash
./ghostpress_batch.py \
  -l client-sites.txt \
  -o /audit-reports/2026-q1 \
  --wpscan-api YOUR_TOKEN \
  -v
```

### Monitoring (Weekly Scans)
```bash
#!/bin/bash
# weekly-scan.sh
./ghostpress_batch.py \
  -l monitored-sites.txt \
  -o /scans/$(date +%Y-%m-%d) \
  --wpscan-api YOUR_TOKEN \
  --resume \
  -y
```

### Bug Bounty (Target Portfolio)
```bash
./ghostpress_batch.py \
  -l bug-bounty-targets.txt \
  -o /bounty/scans \
  -d 5 \
  --skip-nmap \
  --resume
```

## 🔮 Future Enhancements

Coming in future versions:
- Parallel scanning mode (configurable concurrency)
- Consolidated batch report (HTML dashboard)
- CSV export of all findings
- Email notifications on completion
- Retry failed domains automatically
- Integration with CI/CD pipelines

## 📞 Support

- Main docs: `README.md`
- Quick start: `QUICKSTART.md`
- Report issues: GitHub (when published)

---

**Version:** 1.0
**Last Updated:** 2026-02-12
**License:** MIT
