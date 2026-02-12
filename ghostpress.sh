#!/bin/bash

#===============================================================================
# GhostPress - WordPress Non-Intrusive Vulnerability Assessment Tool
# Author: CyberSec Architect
# Version: 2.0
# Description: Enhanced automated passive and active reconnaissance for WP sites
# WARNING: Ensure you have written authorization before running
#===============================================================================

set -euo pipefail  # Strict mode: exit on error, undefined vars, pipe failures

#-------------------------------------------------------------------------------
# CONFIGURATION
#-------------------------------------------------------------------------------

# Script metadata
SCRIPT_VERSION="2.0"
SCRIPT_NAME="GhostPress"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.ghostpress"
CONFIG_FILE="$CONFIG_DIR/config"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Default values (can be overridden by config file)
TARGET=""
OUTPUT_DIR="./ghostpress-scan-$(date +%Y%m%d-%H%M%S)"
THREADS=5
RATE_LIMIT=10
TIMEOUT=30
STEALTH_DELAY=2
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
MAX_USER_ENUM=20
VERBOSE=false
QUIET=false
DRY_RUN=false
SKIP_NMAP=false
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""

# Tools check list
REQUIRED_TOOLS=("curl" "dig" "whois" "jq")
OPTIONAL_TOOLS=("nmap" "whatweb" "wpscan" "nuclei" "sslscan" "ffuf" "parallel" "python3")

# Error log file
ERROR_LOG=""

# Progress tracking
TOTAL_STEPS=0
CURRENT_STEP=0

# Findings database (associative array for structured findings)
declare -A FINDINGS_DB

#-------------------------------------------------------------------------------
# UTILITY FUNCTIONS
#-------------------------------------------------------------------------------

# Enhanced logging with levels and file output
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_file="$OUTPUT_DIR/ghostpress.log"

    # Skip non-error messages in quiet mode
    [[ "$QUIET" == true ]] && [[ "$level" != "ERROR" ]] && [[ "$level" != "CRITICAL" ]] && return 0

    case "$level" in
        INFO)
            [[ "$VERBOSE" == true ]] && echo -e "${GREEN}[+]${NC} ${timestamp} - $message"
            echo "[INFO] ${timestamp} - $message" >> "$log_file" 2>/dev/null || true
            ;;
        WARN)
            echo -e "${YELLOW}[!]${NC} ${timestamp} - $message"
            echo "[WARN] ${timestamp} - $message" >> "$log_file" 2>/dev/null || true
            ;;
        ERROR)
            echo -e "${RED}[-]${NC} ${timestamp} - $message" >&2
            echo "[ERROR] ${timestamp} - $message" >> "$log_file" 2>/dev/null || true
            echo "[ERROR] ${timestamp} - $message" >> "$ERROR_LOG" 2>/dev/null || true
            ;;
        CRITICAL)
            echo -e "${RED}[✗]${NC} ${timestamp} - CRITICAL: $message" >&2
            echo "[CRITICAL] ${timestamp} - $message" >> "$log_file" 2>/dev/null || true
            echo "[CRITICAL] ${timestamp} - $message" >> "$ERROR_LOG" 2>/dev/null || true
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} ${timestamp} - $message"
            echo "[SUCCESS] ${timestamp} - $message" >> "$log_file" 2>/dev/null || true
            ;;
        PHASE)
            echo -e "\n${CYAN}══════════════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}[*] PHASE $message${NC}"
            echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
            echo "[PHASE] ${timestamp} - PHASE $message" >> "$log_file" 2>/dev/null || true
            ;;
        FINDING)
            local severity="$3"
            echo -e "${MAGENTA}[F]${NC} ${timestamp} - [$severity] $message"
            echo "[FINDING] ${timestamp} - [$severity] $message" >> "$log_file" 2>/dev/null || true
            ;;
    esac
}

# Progress indicator
show_progress() {
    [[ "$QUIET" == true ]] && return 0
    [[ "$VERBOSE" == false ]] && return 0

    ((CURRENT_STEP++))
    local percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local filled=$((CURRENT_STEP * 50 / TOTAL_STEPS))
    local empty=$((50 - filled))

    printf "\r${BLUE}Progress:${NC} ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] %3d%% (%d/%d)" "$percent" "$CURRENT_STEP" "$TOTAL_STEPS"
}

# Add finding to structured database
add_finding() {
    local title="$1"
    local severity="$2"
    local description="$3"
    local impact="$4"
    local mitigation="$5"
    local category="${6:-General}"
    local evidence="${7:-N/A}"

    local finding_id="FINDING_$(date +%s%N)"

    FINDINGS_DB["${finding_id}_title"]="$title"
    FINDINGS_DB["${finding_id}_severity"]="$severity"
    FINDINGS_DB["${finding_id}_description"]="$description"
    FINDINGS_DB["${finding_id}_impact"]="$impact"
    FINDINGS_DB["${finding_id}_mitigation"]="$mitigation"
    FINDINGS_DB["${finding_id}_category"]="$category"
    FINDINGS_DB["${finding_id}_evidence"]="$evidence"

    log "FINDING" "$title" "$severity"

    # Write to findings JSON
    echo "$finding_id" >> "$OUTPUT_DIR/findings_ids.txt"
}

# Export findings to JSON
export_findings_json() {
    local json_file="$OUTPUT_DIR/reports/findings.json"

    echo "{" > "$json_file"
    echo "  \"scan_metadata\": {" >> "$json_file"
    echo "    \"target\": \"$TARGET\"," >> "$json_file"
    echo "    \"scan_date\": \"$(date -Iseconds)\"," >> "$json_file"
    echo "    \"tool_version\": \"$SCRIPT_VERSION\"" >> "$json_file"
    echo "  }," >> "$json_file"
    echo "  \"findings\": [" >> "$json_file"

    local first=true
    if [[ -f "$OUTPUT_DIR/findings_ids.txt" ]]; then
        while IFS= read -r finding_id; do
            [[ "$first" == false ]] && echo "," >> "$json_file"
            first=false

            echo "    {" >> "$json_file"
            echo "      \"id\": \"$finding_id\"," >> "$json_file"
            echo "      \"title\": $(echo "${FINDINGS_DB["${finding_id}_title"]}" | jq -R .)," >> "$json_file"
            echo "      \"severity\": \"${FINDINGS_DB["${finding_id}_severity"]}\"," >> "$json_file"
            echo "      \"description\": $(echo "${FINDINGS_DB["${finding_id}_description"]}" | jq -R .)," >> "$json_file"
            echo "      \"impact\": $(echo "${FINDINGS_DB["${finding_id}_impact"]}" | jq -R .)," >> "$json_file"
            echo "      \"mitigation\": $(echo "${FINDINGS_DB["${finding_id}_mitigation"]}" | jq -R .)," >> "$json_file"
            echo "      \"category\": \"${FINDINGS_DB["${finding_id}_category"]}\"," >> "$json_file"
            echo "      \"evidence\": $(echo "${FINDINGS_DB["${finding_id}_evidence"]}" | jq -R .)" >> "$json_file"
            echo -n "    }" >> "$json_file"
        done < "$OUTPUT_DIR/findings_ids.txt"
    fi

    echo "" >> "$json_file"
    echo "  ]" >> "$json_file"
    echo "}" >> "$json_file"

    log "INFO" "Findings exported to JSON: $json_file"
}

# Enhanced stealth curl with proper error handling and SSL validation
stealth_curl() {
    local url="$1"
    local output_file="$2"
    local extra_opts="${3:-}"

    [[ "$DRY_RUN" == true ]] && { log "INFO" "[DRY-RUN] Would fetch: $url"; return 0; }

    sleep "$STEALTH_DELAY"

    if ! curl -sSL \
        --max-time "$TIMEOUT" \
        --connect-timeout 10 \
        -A "$USER_AGENT" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -H "Accept-Encoding: gzip, deflate" \
        -H "DNT: 1" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        --compressed \
        $extra_opts \
        "$url" -o "$output_file" 2>/dev/null; then
        log "ERROR" "Failed to fetch: $url"
        return 1
    fi

    return 0
}

# HTTP request with status code check and false positive reduction
stealth_curl_check() {
    local url="$1"

    [[ "$DRY_RUN" == true ]] && { echo "200"; return 0; }

    sleep "$STEALTH_DELAY"

    local response=$(curl -sSL \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}" \
        "$url" 2>/dev/null || echo "HTTP_CODE:000")

    local http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    local size=$(echo "$response" | grep "SIZE:" | cut -d: -f2)
    local body=$(echo "$response" | sed '/HTTP_CODE:/d' | sed '/SIZE:/d')

    # False positive reduction: check if it's a real 200 or a custom 404 page
    if [[ "$http_code" == "200" ]]; then
        # Check for common 404 indicators in body
        if echo "$body" | grep -qi "not found\|404\|page doesn't exist"; then
            http_code="404"
        fi
        # Check for suspiciously small or large responses
        if [[ "$size" -lt 10 ]] || [[ "$size" -gt 10000000 ]]; then
            log "WARN" "Suspicious response size for $url: $size bytes"
        fi
    fi

    echo "$http_code:$size"
}

# Load configuration file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from: $CONFIG_FILE"
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    fi
}

# Check prerequisites with version checks
check_prerequisites() {
    log "INFO" "Checking prerequisites..."

    local missing_tools=()
    local outdated_tools=()

    # Check required tools
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        log "INFO" "Run: sudo apt-get install ${missing_tools[*]}"
        log "INFO" "Or run: ./install.sh --install-deps"
        exit 1
    fi

    # Check optional tools
    local optional_missing=()
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            optional_missing+=("$tool")
        fi
    done

    if [[ ${#optional_missing[@]} -gt 0 ]]; then
        log "WARN" "Missing optional tools: ${optional_missing[*]}"
        log "INFO" "Some features may be limited. Install with: ./install.sh --install-deps"
    fi

    # Check nuclei templates
    if command -v nuclei &> /dev/null; then
        if [[ ! -d "$HOME/nuclei-templates" ]] && [[ ! -d "/root/nuclei-templates" ]]; then
            log "WARN" "Nuclei templates not found. Run: nuclei -update-templates"
        fi
    fi

    # Check Python for report generation
    if command -v python3 &> /dev/null; then
        if ! python3 -c "import openpyxl" 2>/dev/null; then
            log "WARN" "Python openpyxl module not found. XLSX reports will be unavailable."
            log "INFO" "Install with: pip3 install openpyxl jinja2"
        fi
    fi

    # Create directory structure with severity-based organization
    mkdir -p "$OUTPUT_DIR"/{phase1-passive,phase2-active,phase3-config,reports,findings/{critical,high,medium,low,info}}

    # Initialize log files
    ERROR_LOG="$OUTPUT_DIR/errors.log"
    touch "$ERROR_LOG"
    touch "$OUTPUT_DIR/ghostpress.log"
    touch "$OUTPUT_DIR/findings_ids.txt"

    # Validate and normalize target
    if [[ "$TARGET" =~ ^https?:// ]]; then
        TARGET=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    fi

    # Check if target is reachable
    if ! curl -s --max-time 5 "https://$TARGET" > /dev/null 2>&1; then
        log "WARN" "Target may not be reachable: $TARGET"
        log "INFO" "Continuing anyway..."
    fi

    log "SUCCESS" "Prerequisites check complete"
    log "INFO" "Output directory: $OUTPUT_DIR"
    log "INFO" "Target: $TARGET"
    log "INFO" "Threads: $THREADS | Stealth Delay: ${STEALTH_DELAY}s | Timeout: ${TIMEOUT}s"
}

#-------------------------------------------------------------------------------
# PHASE 1: PASSIVE RECONNAISSANCE
#-------------------------------------------------------------------------------

phase1_passive_recon() {
    log "PHASE" "1: PASSIVE RECONNAISSANCE (OSINT & Infrastructure Mapping)"

    [[ "$SKIP_PHASE1" == true ]] && { log "WARN" "Skipping Phase 1"; return 0; }

    local outdir="$OUTPUT_DIR/phase1-passive"
    local phase_steps=7
    local step=0

    # 1.1 DNS & WHOIS Enumeration
    log "INFO" "Performing DNS and WHOIS enumeration..."
    ((step++))

    {
        echo "=== DNS Records ==="
        dig +short A "$TARGET" 2>/dev/null || log "ERROR" "Failed to query A records"
        echo -e "\n=== AAAA Records ==="
        dig +short AAAA "$TARGET" 2>/dev/null || log "ERROR" "Failed to query AAAA records"
        echo -e "\n=== MX Records ==="
        dig +short MX "$TARGET" 2>/dev/null || log "ERROR" "Failed to query MX records"
        echo -e "\n=== NS Records ==="
        dig +short NS "$TARGET" 2>/dev/null || log "ERROR" "Failed to query NS records"
        echo -e "\n=== TXT Records (SPF, DKIM, DMARC) ==="
        dig +short TXT "$TARGET" 2>/dev/null || log "ERROR" "Failed to query TXT records"
        echo -e "\n=== WHOIS Information ==="
        whois "$TARGET" 2>/dev/null | head -50 || log "ERROR" "Failed to query WHOIS"
    } > "$outdir/dns-whois-info.txt"

    # Check for DNS issues
    if ! dig +short A "$TARGET" &>/dev/null; then
        add_finding \
            "DNS Resolution Failure" \
            "INFO" \
            "Unable to resolve DNS A records for $TARGET" \
            "Target may not be accessible or DNS is misconfigured" \
            "Verify DNS configuration and ensure target is reachable" \
            "Infrastructure"
    fi

    # 1.2 Subdomain Enumeration (passive sources)
    log "INFO" "Checking for subdomains via certificate transparency..."
    ((step++))

    if ! curl -s "https://crt.sh/?q=%.$TARGET&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sort -u > "$outdir/subdomains-crtsh.txt"; then
        log "ERROR" "Failed to enumerate subdomains via crt.sh"
    else
        local subdomain_count=$(wc -l < "$outdir/subdomains-crtsh.txt")
        log "INFO" "Found $subdomain_count subdomains via certificate transparency"

        if [[ "$subdomain_count" -gt 50 ]]; then
            add_finding \
                "Large Subdomain Exposure" \
                "LOW" \
                "Discovered $subdomain_count subdomains via certificate transparency" \
                "Large attack surface, potential for subdomain takeover" \
                "Review subdomains for unused/misconfigured entries" \
                "Information Disclosure" \
                "See: $outdir/subdomains-crtsh.txt"
        fi
    fi

    # 1.3 Technology Fingerprinting
    log "INFO" "Fingerprinting technologies with WhatWeb..."
    ((step++))

    if command -v whatweb &> /dev/null; then
        if ! whatweb -a 3 --log-json="$outdir/whatweb-fingerprint.json" "https://$TARGET" 2>/dev/null; then
            log "ERROR" "WhatWeb fingerprinting failed"
        fi
    else
        log "WARN" "WhatWeb not installed, skipping technology fingerprinting"
    fi

    # 1.4 HTTP Response Analysis
    log "INFO" "Analyzing HTTP responses..."
    ((step++))

    stealth_curl "https://$TARGET" "$outdir/homepage-source.html" || log "ERROR" "Failed to fetch homepage"
    stealth_curl "https://$TARGET/robots.txt" "$outdir/robots.txt" || log "INFO" "No robots.txt found"
    stealth_curl "https://$TARGET/sitemap.xml" "$outdir/sitemap.xml" || log "INFO" "No sitemap.xml found"
    stealth_curl "https://$TARGET/sitemap_index.xml" "$outdir/sitemap_index.xml" || log "INFO" "No sitemap_index.xml found"

    # Check robots.txt for sensitive paths
    if [[ -f "$outdir/robots.txt" ]] && [[ -s "$outdir/robots.txt" ]]; then
        if grep -qi "disallow.*admin\|disallow.*backup\|disallow.*private" "$outdir/robots.txt"; then
            add_finding \
                "Sensitive Paths in robots.txt" \
                "LOW" \
                "robots.txt file reveals potentially sensitive paths" \
                "Information disclosure - attackers can identify restricted areas" \
                "Review robots.txt and remove references to sensitive directories" \
                "Information Disclosure" \
                "See: $outdir/robots.txt"
        fi
    fi

    # 1.5 WordPress Core Files Check
    log "INFO" "Checking WordPress core files..."
    ((step++))

    local wp_files=("readme.html" "license.txt" "wp-links-opml.php")

    if command -v parallel &> /dev/null && [[ "$DRY_RUN" == false ]]; then
        # Use GNU parallel for faster checks
        printf "%s\n" "${wp_files[@]}" | \
            parallel -j "$THREADS" "curl -sSL -A '$USER_AGENT' --max-time $TIMEOUT -o '$outdir/wp-file-{/}.txt' 'https://$TARGET/{}' 2>/dev/null || true"
    else
        # Fallback to backgrounding
        for file in "${wp_files[@]}"; do
            stealth_curl "https://$TARGET/$file" "$outdir/wp-file-${file//\//-}.txt" &
        done
        wait
    fi

    # Check for version disclosure in readme.html
    if [[ -f "$outdir/wp-file-readme.html" ]] && [[ -s "$outdir/wp-file-readme.html" ]]; then
        if grep -qi "version" "$outdir/wp-file-readme.html"; then
            add_finding \
                "WordPress Version Disclosure (readme.html)" \
                "LOW" \
                "readme.html file is accessible and may disclose WordPress version" \
                "Version information helps attackers identify known vulnerabilities" \
                "Remove or restrict access to readme.html file" \
                "Information Disclosure" \
                "File: https://$TARGET/readme.html"
        fi
    fi

    # 1.6 WordPress Specific Passive Checks
    log "INFO" "Performing WordPress-specific passive checks..."
    ((step++))

    if [[ -f "$outdir/homepage-source.html" ]]; then
        # Extract generator meta
        grep -i "generator" "$outdir/homepage-source.html" | head -5 > "$outdir/wp-generator-meta.txt" 2>/dev/null || true

        # Extract themes with versions
        grep -oP 'wp-content/themes/[^/]+/[^?]*\?ver=[\d.]+' "$outdir/homepage-source.html" | sort -u > "$outdir/wp-themes-with-versions.txt" 2>/dev/null || true
        grep -oP 'wp-content/themes/[^/"]+' "$outdir/homepage-source.html" | sort -u > "$outdir/wp-themes-detected.txt" 2>/dev/null || true

        # Extract plugins with versions
        grep -oP 'wp-content/plugins/[^/]+/[^?]*\?ver=[\d.]+' "$outdir/homepage-source.html" | sort -u > "$outdir/wp-plugins-with-versions.txt" 2>/dev/null || true
        grep -oP 'wp-content/plugins/[^/"]+' "$outdir/homepage-source.html" | sort -u > "$outdir/wp-plugins-detected.txt" 2>/dev/null || true

        # Check for debug mode
        if grep -qi "WP_DEBUG\|define.*DEBUG.*true" "$outdir/homepage-source.html"; then
            add_finding \
                "WordPress Debug Mode Enabled" \
                "MEDIUM" \
                "WordPress appears to be running in debug mode" \
                "Debug information disclosure, potential exposure of sensitive data and file paths" \
                "Disable WP_DEBUG in wp-config.php for production environments" \
                "Configuration" \
                "Detected in page source"
        fi

        # Check for generator meta tag
        if [[ -s "$outdir/wp-generator-meta.txt" ]]; then
            add_finding \
                "WordPress Version in Meta Generator Tag" \
                "LOW" \
                "WordPress version is exposed in HTML meta generator tag" \
                "Version disclosure aids vulnerability identification" \
                "Remove generator meta tag using remove_action('wp_head', 'wp_generator')" \
                "Information Disclosure" \
                "See: $outdir/wp-generator-meta.txt"
        fi
    fi

    # 1.7 Check RSS feeds for version leakage
    log "INFO" "Checking RSS feed for version information..."
    ((step++))

    stealth_curl "https://$TARGET/feed/" "$outdir/rss-feed.xml" || log "INFO" "No RSS feed found"

    if [[ -f "$outdir/rss-feed.xml" ]]; then
        grep -oP '(?<=<generator>)[^<]+' "$outdir/rss-feed.xml" > "$outdir/wp-version-rss.txt" 2>/dev/null || true

        if [[ -s "$outdir/wp-version-rss.txt" ]]; then
            local wp_version=$(cat "$outdir/wp-version-rss.txt" | head -1)
            add_finding \
                "WordPress Version Disclosed in RSS Feed" \
                "LOW" \
                "WordPress version $wp_version is exposed in RSS feed generator tag" \
                "Version disclosure enables targeted attacks against known vulnerabilities" \
                "Filter RSS generator tag or use a security plugin to hide version" \
                "Information Disclosure" \
                "Version: $wp_version"
        fi
    fi

    # 1.8 TimThumb detection
    log "INFO" "Checking for TimThumb library..."
    ((step++))

    local timthumb_paths=("thumb.php" "timthumb.php" "scripts/timthumb.php" "wp-content/themes/*/thumb.php")
    for path in "${timthumb_paths[@]}"; do
        local result=$(stealth_curl_check "https://$TARGET/$path")
        if [[ "$result" =~ ^200 ]]; then
            add_finding \
                "TimThumb Script Detected" \
                "HIGH" \
                "TimThumb script found at /$path - known for RCE vulnerabilities" \
                "Remote Code Execution if using vulnerable version (< 2.8.14)" \
                "Update TimThumb to latest version or remove if unused" \
                "Vulnerability" \
                "Path: https://$TARGET/$path"
        fi
    done

    log "SUCCESS" "Phase 1 complete. Results saved to: $outdir"
}

#-------------------------------------------------------------------------------
# PHASE 2: NON-INTRUSIVE ACTIVE SCANNING
#-------------------------------------------------------------------------------

phase2_active_scanning() {
    log "PHASE" "2: NON-INTRUSIVE ACTIVE SCANNING"

    [[ "$SKIP_PHASE2" == true ]] && { log "WARN" "Skipping Phase 2"; return 0; }

    local outdir="$OUTPUT_DIR/phase2-active"

    # 2.1 Nmap WordPress Scripts (optional, can be skipped)
    if [[ "$SKIP_NMAP" == false ]] && command -v nmap &> /dev/null; then
        log "INFO" "Running Nmap WordPress NSE scripts..."

        if ! nmap -Pn -p 80,443 \
            --script http-wordpress-enum,http-wordpress-users \
            --script-args "http-wordpress-enum.search-limit=10,http-wordpress-enum.threads=$THREADS" \
            --max-retries 1 \
            --host-timeout 10m \
            -oN "$outdir/nmap-wordpress.txt" \
            -oX "$outdir/nmap-wordpress.xml" \
            "$TARGET" 2>/dev/null; then
            log "WARN" "Nmap scan encountered issues"
        fi
    else
        log "INFO" "Skipping Nmap scan (--skip-nmap or nmap not installed)"
    fi

    # 2.2 WPScan (Non-intrusive mode)
    if command -v wpscan &> /dev/null; then
        log "INFO" "Running WPScan in stealthy mode..."

        local wpscan_opts="--stealthy --throttle $((STEALTH_DELAY * 1000)) --random-user-agent --request-timeout $TIMEOUT --connect-timeout $TIMEOUT --max-threads $THREADS"

        if [[ -n "${WPSCAN_API_TOKEN:-}" ]]; then
            wpscan_opts="$wpscan_opts --api-token $WPSCAN_API_TOKEN"
            log "INFO" "WPScan API token detected - vulnerability detection enabled"
        else
            log "WARN" "No WPScan API token provided - vulnerability detection limited"
        fi

        if ! wpscan --url "https://$TARGET" \
            $wpscan_opts \
            --enumerate vp,vt,cb,dbe,u1-10 \
            --plugins-detection mixed \
            --no-update \
            -f json \
            -o "$outdir/wpscan-results.json" 2>/dev/null; then
            log "ERROR" "WPScan encountered errors"
        else
            # Parse WPScan results for vulnerabilities
            if [[ -f "$outdir/wpscan-results.json" ]]; then
                local vuln_count=$(jq '[.plugins[]?.vulnerabilities[]?, .themes[]?.vulnerabilities[]?] | length' "$outdir/wpscan-results.json" 2>/dev/null || echo "0")

                if [[ "$vuln_count" -gt 0 ]]; then
                    log "WARN" "WPScan found $vuln_count vulnerabilities"

                    # Extract high/critical vulnerabilities
                    jq -r '.plugins[]?.vulnerabilities[]? | select(.cvss.score >= 7.0) | "\(.title)|\(.cvss.score)"' "$outdir/wpscan-results.json" 2>/dev/null | while IFS='|' read -r title score; do
                        add_finding \
                            "Plugin Vulnerability: $title" \
                            "HIGH" \
                            "Vulnerable plugin detected with CVSS score: $score" \
                            "Plugin vulnerabilities can lead to site compromise, data breach, or RCE" \
                            "Update affected plugins immediately" \
                            "Vulnerability" \
                            "Source: WPScan"
                    done
                fi
            fi
        fi
    else
        log "WARN" "WPScan not installed, skipping WordPress-specific scanning"
    fi

    # 2.3 Nuclei WordPress Templates (optimized)
    if command -v nuclei &> /dev/null; then
        log "INFO" "Running Nuclei with WordPress templates..."

        local nuclei_templates=(
            "$HOME/nuclei-templates/http/technologies/wordpress/"
            "$HOME/nuclei-templates/http/vulnerabilities/wordpress/"
            "$HOME/nuclei-templates/http/exposures/configs/wp-config.yaml"
        )

        local template_args=""
        for template in "${nuclei_templates[@]}"; do
            [[ -e "$template" ]] && template_args="$template_args -t $template"
        done

        if [[ -n "$template_args" ]]; then
            if ! nuclei -u "https://$TARGET" \
                $template_args \
                -rate-limit "$RATE_LIMIT" \
                -c "$THREADS" \
                -timeout "$TIMEOUT" \
                -severity low,medium,high,critical \
                -exclude-tags intrusive,brute-force,dos,fuzzing \
                -json \
                -o "$outdir/nuclei-wordpress.json" 2>/dev/null; then
                log "ERROR" "Nuclei scan encountered issues"
            else
                # Parse Nuclei results
                if [[ -f "$outdir/nuclei-wordpress.json" ]]; then
                    jq -r '. | "\(.info.name)|\(.info.severity)|\(.info.description)"' "$outdir/nuclei-wordpress.json" 2>/dev/null | while IFS='|' read -r name severity desc; do
                        local sev_upper=$(echo "$severity" | tr '[:lower:]' '[:upper:]')
                        add_finding \
                            "$name" \
                            "$sev_upper" \
                            "$desc" \
                            "Identified by Nuclei scanner" \
                            "Review Nuclei output for specific remediation steps" \
                            "Vulnerability" \
                            "Source: Nuclei"
                    done
                fi
            fi
        else
            log "WARN" "Nuclei templates not found"
        fi
    else
        log "WARN" "Nuclei not installed, skipping vulnerability scanning"
    fi

    # 2.4 Content Discovery (Lightweight)
    log "INFO" "Performing lightweight content discovery..."

    if [[ -f "$WORDLIST" ]]; then
        if command -v ffuf &> /dev/null; then
            if ! ffuf -u "https://$TARGET/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,401,500 \
                -t "$THREADS" \
                -p "$STEALTH_DELAY" \
                -H "User-Agent: $USER_AGENT" \
                -o "$outdir/content-discovery.json" \
                -s \
                2>/dev/null; then
                log "ERROR" "Content discovery failed"
            fi
        else
            # Fallback: check critical paths
            log "INFO" "Using fallback content discovery method"
            local critical_paths=(
                "wp-admin" "wp-login.php" "wp-content" "wp-includes"
                "xmlrpc.php" "wp-json" "wp-content/uploads" "wp-content/backup-db"
                ".env" ".git" ".svn" "backup" "wp-config.php.bak"
                "wp-config.php.old" "wp-config.php.save" ".htaccess.bak"
            )

            for path in "${critical_paths[@]}"; do
                local result=$(stealth_curl_check "https://$TARGET/$path")
                local status=$(echo "$result" | cut -d: -f1)
                local size=$(echo "$result" | cut -d: -f2)

                echo "$status - $path (size: $size bytes)" >> "$outdir/critical-paths.txt"

                # Add findings for critical exposures
                if [[ "$status" == "200" ]]; then
                    case "$path" in
                        *.bak|*.old|*.save|*.backup)
                            add_finding \
                                "Backup File Accessible: $path" \
                                "CRITICAL" \
                                "Backup file is publicly accessible at /$path" \
                                "Backup files may contain sensitive configuration, credentials, or source code" \
                                "Remove backup files from web-accessible directories immediately" \
                                "Exposure" \
                                "URL: https://$TARGET/$path"
                            ;;
                        .env|.git|.svn)
                            add_finding \
                                "Sensitive File Exposure: $path" \
                                "CRITICAL" \
                                "Sensitive file/directory is publicly accessible: /$path" \
                                "Exposure of environment files or version control can lead to full compromise" \
                                "Remove $path from public web directory and block access via .htaccess" \
                                "Exposure" \
                                "URL: https://$TARGET/$path"
                            ;;
                    esac
                fi
            done
        fi
    else
        log "WARN" "Wordlist not found at $WORDLIST, skipping content discovery"
    fi

    log "SUCCESS" "Phase 2 complete. Results saved to: $outdir"
}

#-------------------------------------------------------------------------------
# PHASE 3: CONFIGURATION & SECURITY ANALYSIS
#-------------------------------------------------------------------------------

phase3_config_analysis() {
    log "PHASE" "3: CONFIGURATION & SECURITY ANALYSIS"

    [[ "$SKIP_PHASE3" == true ]] && { log "WARN" "Skipping Phase 3"; return 0; }

    local outdir="$OUTPUT_DIR/phase3-config"

    # 3.1 SSL/TLS Configuration Analysis
    log "INFO" "Analyzing SSL/TLS configuration..."

    if command -v sslscan &> /dev/null; then
        if ! sslscan --no-failed "$TARGET:443" > "$outdir/sslscan-results.txt" 2>/dev/null; then
            log "ERROR" "SSL scan failed"
        else
            # Check for weak ciphers
            if grep -qi "weak\|null\|export\|anon\|SSLv2\|SSLv3" "$outdir/sslscan-results.txt"; then
                add_finding \
                    "Weak SSL/TLS Configuration" \
                    "MEDIUM" \
                    "Weak ciphers or outdated protocols detected in SSL/TLS configuration" \
                    "Vulnerable to MITM attacks, POODLE, BEAST, and other SSL/TLS exploits" \
                    "Disable SSLv2/SSLv3, weak ciphers, and enable TLS 1.2+ only" \
                    "Configuration" \
                    "See: $outdir/sslscan-results.txt"
            fi
        fi
    else
        log "WARN" "sslscan not installed, skipping SSL/TLS analysis"
    fi

    # 3.2 Security Headers Analysis
    log "INFO" "Analyzing security headers..."

    local headers_file="$outdir/security-headers.txt"
    local response=$(curl -sSLI \
        -A "$USER_AGENT" \
        --max-time "$TIMEOUT" \
        "https://$TARGET" 2>/dev/null || echo "")

    {
        echo "=== Security Headers Analysis for $TARGET ==="
        echo "Timestamp: $(date)"
        echo ""
        echo "$response"
        echo ""
        echo "=== Missing Security Headers ==="

        # Check for missing headers with detailed impact
        declare -A security_headers=(
            ["Strict-Transport-Security"]="HSTS protects against SSL stripping attacks"
            ["X-Frame-Options"]="Prevents clickjacking attacks"
            ["X-Content-Type-Options"]="Prevents MIME-type sniffing attacks"
            ["Referrer-Policy"]="Controls referrer information disclosure"
            ["Content-Security-Policy"]="Mitigates XSS and injection attacks"
            ["X-XSS-Protection"]="Enables browser XSS filtering"
            ["Permissions-Policy"]="Controls browser feature access"
        )

        for header in "${!security_headers[@]}"; do
            if ! echo "$response" | grep -qi "^$header:"; then
                echo "[MISSING] $header - ${security_headers[$header]}"

                # Add finding for each missing critical header
                local severity="MEDIUM"
                [[ "$header" == "Content-Security-Policy" ]] && severity="HIGH"
                [[ "$header" == "X-Frame-Options" ]] && severity="HIGH"

                add_finding \
                    "Missing Security Header: $header" \
                    "$severity" \
                    "Security header $header is not configured" \
                    "${security_headers[$header]}" \
                    "Configure $header in web server or WordPress security plugin" \
                    "Configuration" \
                    "Header not present in HTTP response"
            fi
        done

        echo ""
        echo "=== WordPress Specific Checks ==="

        # Check for information disclosure headers
        if echo "$response" | grep -qi "X-Powered-By.*PHP"; then
            echo "[WARNING] X-Powered-By header exposes PHP version (information disclosure)"
            add_finding \
                "PHP Version Disclosure" \
                "LOW" \
                "X-Powered-By header exposes PHP version information" \
                "Assists attackers in identifying PHP-specific vulnerabilities" \
                "Remove X-Powered-By header via expose_php=Off in php.ini" \
                "Information Disclosure" \
                "Header present in HTTP response"
        fi

        if echo "$response" | grep -qi "Server:"; then
            local server_header=$(echo "$response" | grep -i "^Server:" | head -1)
            echo "[INFO] Server header present: $server_header"
        fi

    } > "$headers_file"

    # 3.3 WordPress REST API Enumeration
    log "INFO" "Enumerating WordPress REST API..."

    local api_checks=(
        "wp-json/"
        "wp-json/wp/v2/"
        "wp-json/wp/v2/users/"
        "wp-json/wp/v2/posts/"
        "wp-json/wp/v2/pages/"
        "wp-json/wp/v2/media/"
        "wp-json/wp/v2/types/"
        "wp-json/wp/v2/taxonomies/"
    )

    for endpoint in "${api_checks[@]}"; do
        local result=$(stealth_curl_check "https://$TARGET/$endpoint")
        local http_code=$(echo "$result" | cut -d: -f1)
        local size=$(echo "$result" | cut -d: -f2)

        echo "Endpoint: $endpoint - Status: $http_code (Size: $size bytes)" >> "$outdir/api-enumeration.txt"

        # Fetch and save successful responses
        if [[ "$http_code" == "200" ]]; then
            stealth_curl "https://$TARGET/$endpoint" "$outdir/api-${endpoint//\//-}.json" || true

            # Check for user enumeration
            if [[ "$endpoint" == "wp-json/wp/v2/users/" ]]; then
                add_finding \
                    "WordPress REST API User Enumeration" \
                    "MEDIUM" \
                    "WordPress REST API users endpoint is publicly accessible" \
                    "Exposes usernames that can be used for brute-force attacks" \
                    "Restrict REST API access or disable user enumeration via plugin/code" \
                    "Information Disclosure" \
                    "Endpoint: https://$TARGET/$endpoint"
            fi
        fi
    done

    # 3.4 XML-RPC Check
    log "INFO" "Checking XML-RPC status..."

    local xmlrpc_response=$(curl -s -X POST \
        -A "$USER_AGENT" \
        -H "Content-Type: text/xml" \
        --max-time "$TIMEOUT" \
        -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
        "https://$TARGET/xmlrpc.php" 2>/dev/null || echo "")

    {
        echo "=== XML-RPC Analysis ==="
        if echo "$xmlrpc_response" | grep -q "methodResponse"; then
            echo "[ALERT] XML-RPC is enabled and responding"
            echo "Available methods:"
            echo "$xmlrpc_response" | grep -oP '(?<=<string>)[^<]+' | head -20

            add_finding \
                "XML-RPC Enabled" \
                "MEDIUM" \
                "WordPress XML-RPC interface is enabled and responding" \
                "XML-RPC can be exploited for brute-force amplification, DDoS, and pingback attacks" \
                "Disable XML-RPC unless required for specific integrations (use plugin or code)" \
                "Configuration" \
                "Endpoint: https://$TARGET/xmlrpc.php"
        else
            echo "[INFO] XML-RPC not responding or disabled"
        fi
    } > "$outdir/xmlrpc-analysis.txt"

    # 3.5 User Enumeration via Multiple Vectors
    log "INFO" "Checking user enumeration vectors..."

    {
        echo "=== User Enumeration Checks ==="

        # Check author pages (expanded range)
        local users_found=0
        for i in $(seq 1 "$MAX_USER_ENUM"); do
            local result=$(stealth_curl_check "https://$TARGET/?author=$i")
            local author_check=$(echo "$result" | cut -d: -f1)

            if [[ "$author_check" == "200" ]] || [[ "$author_check" == "301" ]]; then
                echo "[FOUND] User ID $i exists (/?author=$i returns $author_check)"
                ((users_found++))
            fi
            sleep 0.5
        done

        if [[ "$users_found" -gt 0 ]]; then
            add_finding \
                "User Enumeration via Author Pages" \
                "LOW" \
                "User enumeration is possible via /?author=N parameter ($users_found users found)" \
                "Exposes valid usernames for brute-force attacks" \
                "Use security plugin to block author enumeration or implement custom code" \
                "Information Disclosure" \
                "Parameter: /?author=N"
        fi

        # Check REST API users (already handled above)
        if [[ -f "$outdir/api-wp-json-wp-v2-users-.json" ]]; then
            echo ""
            echo "[ALERT] REST API user endpoint is accessible"
            jq -r '.[] | "User: \(.name) (ID: \(.id), Slug: \(.slug))"' "$outdir/api-wp-json-wp-v2-users-.json" 2>/dev/null || true
        fi

    } > "$outdir/user-enumeration.txt"

    # 3.6 File Permission & Backup Checks (enhanced with false positive reduction)
    log "INFO" "Checking for exposed files and backups..."

    local backup_extensions=(".bak" ".backup" ".old" ".orig" ".save" ".swp" ".zip" ".tar.gz" ".sql" ".7z" ".rar")
    local critical_files=("wp-config.php" ".htaccess" ".env" "wp-config-sample.php")

    {
        echo "=== Exposed Files & Backup Checks ==="

        for file in "${critical_files[@]}"; do
            for ext in "" "${backup_extensions[@]}"; do
                local check_url="https://$TARGET/$file$ext"
                local result=$(stealth_curl_check "$check_url")
                local status=$(echo "$result" | cut -d: -f1)
                local size=$(echo "$result" | cut -d: -f2)

                if [[ "$status" == "200" ]] && [[ "$size" -gt 50 ]]; then
                    echo "[CRITICAL] Accessible: $check_url (HTTP $status, Size: $size bytes)"

                    # Already added in phase 2, but double-check for backup files
                    if [[ -n "$ext" ]]; then
                        add_finding \
                            "Backup File Accessible: $file$ext" \
                            "CRITICAL" \
                            "Backup file is publicly accessible: /$file$ext" \
                            "Backup files may contain database credentials, API keys, and sensitive configuration" \
                            "Immediately remove backup files from web-accessible directories" \
                            "Exposure" \
                            "URL: $check_url (Size: $size bytes)"
                    fi
                elif [[ "$status" == "403" ]]; then
                    echo "[INFO] Forbidden (protected): $check_url (HTTP $status)"
                fi

                sleep 0.2
            done
        done

        # Check directory indexing
        for dir in "wp-content" "wp-content/uploads" "wp-content/plugins" "wp-content/themes" "wp-includes"; do
            local result=$(stealth_curl_check "https://$TARGET/$dir/")
            local dir_status=$(echo "$result" | cut -d: -f1)

            if [[ "$dir_status" == "200" ]]; then
                # Verify it's actually directory listing
                local dir_content=$(curl -s -A "$USER_AGENT" --max-time "$TIMEOUT" "https://$TARGET/$dir/" 2>/dev/null)
                if echo "$dir_content" | grep -qi "index of\|<title>Index of\|parent directory"; then
                    echo "[WARNING] Directory indexing enabled: https://$TARGET/$dir/"

                    add_finding \
                        "Directory Indexing Enabled: $dir" \
                        "LOW" \
                        "Directory listing is enabled for /$dir/" \
                        "Information disclosure - attackers can browse files and identify vulnerable components" \
                        "Disable directory indexing via .htaccess (Options -Indexes)" \
                        "Information Disclosure" \
                        "URL: https://$TARGET/$dir/"
                fi
            fi
            sleep 0.3
        done

    } > "$outdir/exposed-files-check.txt"

    # 3.7 Additional WordPress-specific checks
    log "INFO" "Performing additional WordPress security checks..."

    # Check for application passwords (WP 5.6+)
    local app_pass_result=$(stealth_curl_check "https://$TARGET/wp-json/wp/v2/users/me/application-passwords")
    if [[ "$app_pass_result" =~ ^200 ]]; then
        add_finding \
            "Application Passwords Endpoint Accessible" \
            "MEDIUM" \
            "WordPress Application Passwords endpoint is accessible" \
            "May allow password creation/management without proper authentication" \
            "Restrict REST API access and monitor application password usage" \
            "Configuration" \
            "Endpoint: /wp-json/wp/v2/users/me/application-passwords"
    fi

    # Check for wp-cron exposure
    local cron_result=$(stealth_curl_check "https://$TARGET/wp-cron.php")
    if [[ "$cron_result" =~ ^200 ]]; then
        log "INFO" "wp-cron.php is accessible (normal behavior)"
        # Note: This is expected, but could be used for DDoS
    fi

    log "SUCCESS" "Phase 3 complete. Results saved to: $outdir"
}

#-------------------------------------------------------------------------------
# REPORTING & EXPORT
#-------------------------------------------------------------------------------

generate_reports() {
    log "INFO" "Generating comprehensive reports..."

    # Export findings to JSON
    export_findings_json

    # Generate Markdown report
    generate_markdown_report

    # Generate HTML report (if Python available)
    if command -v python3 &> /dev/null; then
        if [[ -f "$SCRIPT_DIR/generate_reports.py" ]]; then
            log "INFO" "Generating HTML and XLSX reports..."
            if ! python3 "$SCRIPT_DIR/generate_reports.py" "$OUTPUT_DIR" "$TARGET" 2>>"$ERROR_LOG"; then
                log "ERROR" "Failed to generate HTML/XLSX reports"
            else
                log "SUCCESS" "HTML report: $OUTPUT_DIR/reports/report.html"
                log "SUCCESS" "XLSX report: $OUTPUT_DIR/reports/report.xlsx"
            fi
        else
            log "WARN" "Report generator script not found: generate_reports.py"
        fi
    else
        log "WARN" "Python3 not available - HTML/XLSX reports will not be generated"
    fi

    # Send notifications if webhooks configured
    send_notifications
}

generate_markdown_report() {
    local report_file="$OUTPUT_DIR/reports/report.md"

    # Count findings by severity
    local critical_count=$(grep -c '"severity": "CRITICAL"' "$OUTPUT_DIR/reports/findings.json" 2>/dev/null || echo "0")
    local high_count=$(grep -c '"severity": "HIGH"' "$OUTPUT_DIR/reports/findings.json" 2>/dev/null || echo "0")
    local medium_count=$(grep -c '"severity": "MEDIUM"' "$OUTPUT_DIR/reports/findings.json" 2>/dev/null || echo "0")
    local low_count=$(grep -c '"severity": "LOW"' "$OUTPUT_DIR/reports/findings.json" 2>/dev/null || echo "0")
    local info_count=$(grep -c '"severity": "INFO"' "$OUTPUT_DIR/reports/findings.json" 2>/dev/null || echo "0")

    cat > "$report_file" << EOF
# GhostPress Security Assessment Report

**Target:** $TARGET
**Scan Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool Version:** $SCRIPT_NAME v$SCRIPT_VERSION
**Report Type:** WordPress Non-Intrusive Vulnerability Assessment

---

## Executive Summary

This report presents the findings from an automated security assessment of the WordPress installation at **$TARGET**. The assessment was conducted using non-intrusive techniques to identify potential security vulnerabilities, misconfigurations, and information disclosures.

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | $critical_count |
| 🟠 High | $high_count |
| 🟡 Medium | $medium_count |
| 🔵 Low | $low_count |
| ⚪ Info | $info_count |
| **Total** | **$((critical_count + high_count + medium_count + low_count + info_count))** |

### Risk Assessment

EOF

    # Calculate overall risk score
    local risk_score=$((critical_count * 10 + high_count * 7 + medium_count * 4 + low_count * 2 + info_count * 1))
    local risk_level="Low"

    if [[ "$risk_score" -gt 50 ]]; then
        risk_level="Critical"
    elif [[ "$risk_score" -gt 30 ]]; then
        risk_level="High"
    elif [[ "$risk_score" -gt 15 ]]; then
        risk_level="Medium"
    fi

    cat >> "$report_file" << EOF
**Overall Risk Level:** $risk_level
**Risk Score:** $risk_score / 100

---

## Scope & Methodology

### In Scope
- Passive reconnaissance and OSINT gathering
- Non-intrusive vulnerability scanning
- Configuration and security header analysis
- WordPress-specific security checks

### Out of Scope
- Brute force attacks
- SQL injection testing
- XSS exploitation
- Authenticated testing (without credentials)
- Denial of Service testing

### Assessment Phases

1. **Phase 1 - Passive Reconnaissance**
   - DNS enumeration and WHOIS lookup
   - Subdomain discovery via certificate transparency
   - Technology fingerprinting
   - WordPress version detection

2. **Phase 2 - Active Scanning**
   - WPScan vulnerability detection
   - Nuclei template scanning
   - Content discovery
   - Plugin and theme enumeration

3. **Phase 3 - Configuration Analysis**
   - SSL/TLS configuration review
   - Security headers analysis
   - REST API enumeration
   - XML-RPC status check
   - User enumeration testing
   - File exposure and backup detection

---

## Detailed Findings

EOF

    # Add findings grouped by severity
    for severity in "CRITICAL" "HIGH" "MEDIUM" "LOW" "INFO"; do
        local count_var="${severity,,}_count"
        local count=${!count_var}

        if [[ "$count" -gt 0 ]]; then
            cat >> "$report_file" << EOF

### ${severity} Severity Findings ($count)

EOF

            # Extract findings for this severity
            if [[ -f "$OUTPUT_DIR/findings_ids.txt" ]]; then
                while IFS= read -r finding_id; do
                    if [[ "${FINDINGS_DB["${finding_id}_severity"]}" == "$severity" ]]; then
                        cat >> "$report_file" << EOF

#### ${FINDINGS_DB["${finding_id}_title"]}

**Severity:** ${FINDINGS_DB["${finding_id}_severity"]}
**Category:** ${FINDINGS_DB["${finding_id}_category"]}

**Description:**
${FINDINGS_DB["${finding_id}_description"]}

**Impact:**
${FINDINGS_DB["${finding_id}_impact"]}

**Mitigation:**
${FINDINGS_DB["${finding_id}_mitigation"]}

**Evidence:**
${FINDINGS_DB["${finding_id}_evidence"]}

---

EOF
                    fi
                done < "$OUTPUT_DIR/findings_ids.txt"
            fi
        fi
    done

    cat >> "$report_file" << EOF

## Recommendations

Based on the findings, we recommend the following actions in priority order:

### Immediate Actions (Critical/High)
EOF

    if [[ "$critical_count" -gt 0 ]] || [[ "$high_count" -gt 0 ]]; then
        cat >> "$report_file" << EOF
1. **Address all Critical and High severity findings immediately**
2. **Remove any exposed backup files or sensitive files from web-accessible directories**
3. **Update WordPress core, themes, and plugins to latest versions**
4. **Review and implement missing security headers**
5. **Disable XML-RPC if not required**
EOF
    else
        cat >> "$report_file" << EOF
- No critical or high-severity issues found
EOF
    fi

    cat >> "$report_file" << EOF

### Short-term Actions (Medium)
1. **Implement user enumeration protection**
2. **Review and restrict REST API access**
3. **Configure SSL/TLS settings to use strong ciphers only**
4. **Disable directory indexing**
5. **Remove version disclosure from HTML and RSS feeds**

### Long-term Actions (Low/Informational)
1. **Implement Web Application Firewall (WAF)**
2. **Set up security monitoring and alerting**
3. **Conduct regular security assessments**
4. **Implement least-privilege access controls**
5. **Create incident response procedures**

---

## Technical Details

### Tools Used
- **WPScan:** WordPress vulnerability scanner
- **Nuclei:** Template-based vulnerability scanning
- **SSLScan:** SSL/TLS configuration analysis
- **WhatWeb:** Technology fingerprinting
- **Custom scripts:** HTTP analysis and enumeration

### Scan Configuration
- **Threads:** $THREADS
- **Stealth Delay:** ${STEALTH_DELAY}s
- **Timeout:** ${TIMEOUT}s
- **Rate Limit:** $RATE_LIMIT req/s

---

## Appendix

### Output Directory Structure

\`\`\`
$OUTPUT_DIR/
├── phase1-passive/          # Passive reconnaissance results
├── phase2-active/           # Active scanning results
├── phase3-config/           # Configuration analysis results
├── findings/                # Findings organized by severity
│   ├── critical/
│   ├── high/
│   ├── medium/
│   ├── low/
│   └── info/
└── reports/                 # Generated reports
    ├── report.md           # This report
    ├── report.html         # HTML version
    ├── report.xlsx         # Excel spreadsheet
    └── findings.json       # Machine-readable findings
\`\`\`

### Disclaimer

This assessment was performed using automated tools in non-intrusive mode. Results should be validated manually before taking remediation actions. False positives may occur. This report does not guarantee the security of the assessed system and represents a point-in-time assessment.

---

**Report Generated:** $(date)
**Tool:** $SCRIPT_NAME v$SCRIPT_VERSION
**Confidential:** For authorized use only

EOF

    log "SUCCESS" "Markdown report generated: $report_file"
}

# Send notifications via webhooks
send_notifications() {
    local findings_count=$(($(wc -l < "$OUTPUT_DIR/findings_ids.txt" 2>/dev/null || echo "0")))

    if [[ "$findings_count" -eq 0 ]]; then
        return 0
    fi

    local message="GhostPress scan complete for $TARGET - Found $findings_count findings"

    # Slack notification
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        log "INFO" "Sending Slack notification..."
        curl -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"$message\"}" \
            2>/dev/null || log "ERROR" "Failed to send Slack notification"
    fi

    # Discord notification
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        log "INFO" "Sending Discord notification..."
        curl -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"content\": \"$message\"}" \
            2>/dev/null || log "ERROR" "Failed to send Discord notification"
    fi
}

#-------------------------------------------------------------------------------
# USAGE & ARGUMENT PARSING
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
${CYAN}GhostPress${NC} - WordPress Non-Intrusive Vulnerability Assessment Tool
Version: $SCRIPT_VERSION

${GREEN}Usage:${NC} $0 -t <target> [options]

${YELLOW}Required:${NC}
  -t, --target <domain>       Target domain (e.g., example.com)

${YELLOW}Optional:${NC}
  -o, --output <dir>          Output directory (default: ./ghostpress-scan-TIMESTAMP)
  -c, --config <file>         Configuration file (default: ~/.ghostpress/config)
  -d, --delay <seconds>       Stealth delay between requests (default: 2)
  -r, --rate-limit <num>      Rate limit for nuclei (default: 10)
  -T, --threads <num>         Thread count for tools (default: 5)
  -w, --wordlist <file>       Custom wordlist for content discovery
  -u, --max-users <num>       Maximum user IDs to enumerate (default: 20)

${YELLOW}Scan Control:${NC}
  --skip-phase1               Skip passive reconnaissance
  --skip-phase2               Skip active scanning
  --skip-phase3               Skip configuration analysis
  --skip-nmap                 Skip Nmap scanning
  --wpscan-api <token>        WPScan API token for vulnerability detection

${YELLOW}Behavior:${NC}
  -v, --verbose               Verbose output
  -q, --quiet                 Quiet mode (errors only)
  --dry-run                   Dry run mode (no actual requests)

${YELLOW}Notifications:${NC}
  --slack-webhook <url>       Slack webhook URL for notifications
  --discord-webhook <url>     Discord webhook URL for notifications

${YELLOW}Other:${NC}
  --install-deps              Install required dependencies
  --version                   Show version information
  -h, --help                  Show this help message

${GREEN}Examples:${NC}
  # Basic scan
  $0 -t example.com

  # Full scan with API token and notifications
  $0 -t example.com --wpscan-api YOUR_TOKEN --slack-webhook https://hooks.slack.com/...

  # Stealthy scan with increased delays
  $0 -t example.com -d 5 -T 2 --skip-nmap

  # Quick scan (skip passive recon)
  $0 -t example.com --skip-phase1 -v

${GREEN}Configuration:${NC}
  Create ~/.ghostpress/config to set default values:
    TARGET="example.com"
    THREADS=10
    STEALTH_DELAY=1
    WPSCAN_API_TOKEN="your-token"

${CYAN}Report:${NC} https://github.com/yourusername/ghostpress
EOF
    exit 0
}

# Show version information
show_version() {
    echo "GhostPress v$SCRIPT_VERSION"
    echo "WordPress Non-Intrusive Vulnerability Assessment Tool"
    echo ""
    echo "Required tools:"
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo "  [✓] $tool"
        else
            echo "  [✗] $tool (missing)"
        fi
    done
    echo ""
    echo "Optional tools:"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo "  [✓] $tool"
        else
            echo "  [ ] $tool (not installed)"
        fi
    done
    exit 0
}

# Install dependencies
install_dependencies() {
    echo "Installing GhostPress dependencies..."

    if [[ -f "$SCRIPT_DIR/install.sh" ]]; then
        bash "$SCRIPT_DIR/install.sh" --install-deps
    else
        echo "Error: install.sh script not found"
        exit 1
    fi
}

# Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--delay)
                STEALTH_DELAY="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -u|--max-users)
                MAX_USER_ENUM="$2"
                shift 2
                ;;
            --wpscan-api)
                WPSCAN_API_TOKEN="$2"
                shift 2
                ;;
            --skip-phase1)
                SKIP_PHASE1=true
                shift
                ;;
            --skip-phase2)
                SKIP_PHASE2=true
                shift
                ;;
            --skip-phase3)
                SKIP_PHASE3=true
                shift
                ;;
            --skip-nmap)
                SKIP_NMAP=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --slack-webhook)
                SLACK_WEBHOOK="$2"
                shift 2
                ;;
            --discord-webhook)
                DISCORD_WEBHOOK="$2"
                shift 2
                ;;
            --install-deps)
                install_dependencies
                exit 0
                ;;
            --version)
                show_version
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                usage
                ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# MAIN EXECUTION
#-------------------------------------------------------------------------------

main() {
    # Print banner
    echo -e "${CYAN}"
    cat << "EOF"
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |__) | __ ___  ___ ___
 | | |_ | '_ \ / _ \/ __| __|  ___/ '__/ _ \/ __/ __|
 | |__| | | | | (_) \__ \ |_| |   | | |  __/\__ \__ \
  \_____|_| |_|\___/|___/\__|_|   |_|  \___||___/___/

  WordPress Security Assessment Tool v$SCRIPT_VERSION
  Non-Intrusive Vulnerability Scanner
EOF
    echo -e "${NC}\n"

    # Parse arguments
    parse_arguments "$@"

    # Load configuration
    load_config

    # Validate required arguments
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] Target is required${NC}\n"
        usage
    fi

    # Set skip flags defaults
    SKIP_PHASE1=${SKIP_PHASE1:-false}
    SKIP_PHASE2=${SKIP_PHASE2:-false}
    SKIP_PHASE3=${SKIP_PHASE3:-false}

    # Check prerequisites
    check_prerequisites

    # Calculate total steps for progress tracking
    TOTAL_STEPS=3
    CURRENT_STEP=0

    # Record start time
    local start_time=$(date +%s)

    # Execute phases
    [[ "$SKIP_PHASE1" == false ]] && phase1_passive_recon || log "WARN" "Skipping Phase 1"
    [[ "$SKIP_PHASE2" == false ]] && phase2_active_scanning || log "WARN" "Skipping Phase 2"
    [[ "$SKIP_PHASE3" == false ]] && phase3_config_analysis || log "WARN" "Skipping Phase 3"

    # Generate reports
    generate_reports

    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    # Final summary
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════════${NC}"
    log "SUCCESS" "Assessment complete for: $TARGET"
    log "INFO" "Scan duration: $duration_formatted"
    log "INFO" "Results directory: $OUTPUT_DIR"
    log "INFO" "Reports generated:"
    echo -e "  ${CYAN}→${NC} Markdown: $OUTPUT_DIR/reports/report.md"
    [[ -f "$OUTPUT_DIR/reports/report.html" ]] && echo -e "  ${CYAN}→${NC} HTML: $OUTPUT_DIR/reports/report.html"
    [[ -f "$OUTPUT_DIR/reports/report.xlsx" ]] && echo -e "  ${CYAN}→${NC} Excel: $OUTPUT_DIR/reports/report.xlsx"
    echo -e "  ${CYAN}→${NC} JSON: $OUTPUT_DIR/reports/findings.json"

    # Show findings summary
    local findings_count=$(wc -l < "$OUTPUT_DIR/findings_ids.txt" 2>/dev/null || echo "0")
    if [[ "$findings_count" -gt 0 ]]; then
        log "WARN" "Found $findings_count security findings - review reports for details"
    else
        log "SUCCESS" "No security findings detected"
    fi

    echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}\n"

    # Check for errors
    if [[ -s "$ERROR_LOG" ]]; then
        log "WARN" "Errors occurred during scan - check $ERROR_LOG for details"
    fi
}

# Trap to handle interruptions
trap 'echo -e "\n${RED}[!] Scan interrupted by user${NC}"; exit 130' INT TERM

# Run main function
main "$@"
