#!/bin/bash

#===============================================================================
# GhostPress Installation Script
# Installs all required and optional dependencies
#===============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |__) | __ ___  ___ ___
 | | |_ | '_ \ / _ \/ __| __|  ___/ '__/ _ \/ __/ __|
 | |__| | | | | (_) \__ \ |_| |   | | |  __/\__ \__ \
  \_____|_| |_|\___/|___/\__|_|   |_|  \___||___/___/

  Installation Script
EOF
echo -e "${NC}\n"

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Running as root - will install system-wide${NC}"
    SUDO=""
else
    echo -e "${YELLOW}[!] Running as user - will use sudo for system packages${NC}"
    SUDO="sudo"
fi

install_deps=false
setup_config=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --install-deps)
            install_deps=true
            shift
            ;;
        --setup)
            setup_config=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--install-deps] [--setup]"
            exit 1
            ;;
    esac
done

if [[ "$install_deps" == false ]] && [[ "$setup_config" == false ]]; then
    echo "Usage: $0 [--install-deps] [--setup]"
    echo ""
    echo "Options:"
    echo "  --install-deps    Install all required and optional dependencies"
    echo "  --setup          Setup configuration files and directories"
    exit 0
fi

# Install dependencies
if [[ "$install_deps" == true ]]; then
    echo -e "${GREEN}[+] Installing dependencies...${NC}\n"

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
    else
        echo -e "${RED}[-] Unsupported package manager${NC}"
        exit 1
    fi

    echo -e "${CYAN}[*] Detected package manager: $PKG_MANAGER${NC}\n"

    # Update package lists
    echo -e "${GREEN}[+] Updating package lists...${NC}"
    case $PKG_MANAGER in
        apt-get)
            $SUDO apt-get update -qq
            ;;
        yum|dnf)
            $SUDO $PKG_MANAGER check-update || true
            ;;
        pacman)
            $SUDO pacman -Sy
            ;;
    esac

    # Install core tools
    echo -e "${GREEN}[+] Installing core tools...${NC}"
    case $PKG_MANAGER in
        apt-get)
            $SUDO apt-get install -y -qq curl dnsutils whois jq git
            ;;
        yum|dnf)
            $SUDO $PKG_MANAGER install -y curl bind-utils whois jq git
            ;;
        pacman)
            $SUDO pacman -S --noconfirm curl dnsutils whois jq git
            ;;
    esac

    # Install optional security tools
    echo -e "${GREEN}[+] Installing optional security tools...${NC}"
    case $PKG_MANAGER in
        apt-get)
            $SUDO apt-get install -y -qq nmap sslscan whatweb parallel 2>/dev/null || echo "Some tools failed to install"
            ;;
        yum|dnf)
            $SUDO $PKG_MANAGER install -y nmap sslscan parallel 2>/dev/null || echo "Some tools failed to install"
            ;;
        pacman)
            $SUDO pacman -S --noconfirm nmap sslscan parallel 2>/dev/null || echo "Some tools failed to install"
            ;;
    esac

    # Install Python3 and pip
    echo -e "${GREEN}[+] Installing Python3 and pip...${NC}"
    case $PKG_MANAGER in
        apt-get)
            $SUDO apt-get install -y -qq python3 python3-pip
            ;;
        yum|dnf)
            $SUDO $PKG_MANAGER install -y python3 python3-pip
            ;;
        pacman)
            $SUDO pacman -S --noconfirm python python-pip
            ;;
    esac

    # Install Python packages
    echo -e "${GREEN}[+] Installing Python packages for report generation...${NC}"
    pip3 install --user openpyxl jinja2 2>/dev/null || echo "Python packages installation had issues"

    # Install WPScan (requires Ruby)
    echo -e "${GREEN}[+] Installing WPScan...${NC}"
    if ! command -v wpscan &> /dev/null; then
        case $PKG_MANAGER in
            apt-get)
                $SUDO apt-get install -y -qq ruby-full
                ;;
            yum|dnf)
                $SUDO $PKG_MANAGER install -y ruby rubygems
                ;;
            pacman)
                $SUDO pacman -S --noconfirm ruby
                ;;
        esac
        $SUDO gem install wpscan || echo "WPScan installation failed"
    else
        echo "WPScan already installed"
    fi

    # Install Nuclei
    echo -e "${GREEN}[+] Installing Nuclei...${NC}"
    if ! command -v nuclei &> /dev/null; then
        # Download and install latest Nuclei
        NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        if [[ -n "$NUCLEI_VERSION" ]]; then
            echo "Installing Nuclei $NUCLEI_VERSION..."
            ARCH=$(uname -m)
            case $ARCH in
                x86_64)
                    ARCH="amd64"
                    ;;
                aarch64)
                    ARCH="arm64"
                    ;;
            esac

            wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION:1}_linux_${ARCH}.zip" -O /tmp/nuclei.zip
            unzip -q /tmp/nuclei.zip -d /tmp/
            $SUDO mv /tmp/nuclei /usr/local/bin/
            $SUDO chmod +x /usr/local/bin/nuclei
            rm /tmp/nuclei.zip
            echo "Updating Nuclei templates..."
            nuclei -update-templates -silent
        else
            echo "Failed to determine Nuclei version"
        fi
    else
        echo "Nuclei already installed"
        echo "Updating Nuclei templates..."
        nuclei -update-templates -silent
    fi

    # Install ffuf
    echo -e "${GREEN}[+] Installing ffuf...${NC}"
    if ! command -v ffuf &> /dev/null; then
        case $PKG_MANAGER in
            apt-get)
                $SUDO apt-get install -y -qq ffuf 2>/dev/null || {
                    echo "ffuf not in repos, installing from GitHub..."
                    FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                    if [[ -n "$FFUF_VERSION" ]]; then
                        wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION:1}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz
                        tar -xzf /tmp/ffuf.tar.gz -C /tmp/
                        $SUDO mv /tmp/ffuf /usr/local/bin/
                        $SUDO chmod +x /usr/local/bin/ffuf
                        rm /tmp/ffuf.tar.gz
                    fi
                }
                ;;
            *)
                echo "Please install ffuf manually from https://github.com/ffuf/ffuf"
                ;;
        esac
    else
        echo "ffuf already installed"
    fi

    # Install testssl.sh
    echo -e "${GREEN}[+] Installing testssl.sh...${NC}"
    if ! command -v testssl.sh &> /dev/null; then
        case $PKG_MANAGER in
            apt-get)
                $SUDO apt-get install -y -qq testssl.sh 2>/dev/null || echo "testssl.sh not available in repos"
                ;;
        esac
    else
        echo "testssl.sh already installed"
    fi

    # Download SecLists wordlists
    echo -e "${GREEN}[+] Installing SecLists wordlists...${NC}"
    if [[ ! -d "/usr/share/wordlists/seclists" ]]; then
        $SUDO mkdir -p /usr/share/wordlists
        $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists 2>/dev/null || echo "Failed to clone SecLists"
    else
        echo "SecLists already installed"
    fi

    echo -e "\n${GREEN}[✓] Dependency installation complete!${NC}\n"
fi

# Setup configuration
if [[ "$setup_config" == true ]]; then
    echo -e "${GREEN}[+] Setting up GhostPress configuration...${NC}\n"

    # Create config directory
    CONFIG_DIR="$HOME/.ghostpress"
    mkdir -p "$CONFIG_DIR"

    # Copy config file if not exists
    if [[ ! -f "$CONFIG_DIR/config" ]]; then
        if [[ -f "config.example" ]]; then
            cp config.example "$CONFIG_DIR/config"
            echo -e "${GREEN}[✓] Configuration file created: $CONFIG_DIR/config${NC}"
            echo -e "${YELLOW}[!] Please edit this file to customize your settings${NC}"
        else
            echo -e "${YELLOW}[!] config.example not found, skipping${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Configuration file already exists: $CONFIG_DIR/config${NC}"
    fi

    # Make scripts executable
    chmod +x ghostpress.sh 2>/dev/null || true
    chmod +x generate_reports.py 2>/dev/null || true

    echo -e "\n${GREEN}[✓] Configuration setup complete!${NC}\n"
fi

# Show summary
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] GhostPress installation complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}\n"

echo "Installed tools:"
for tool in curl dig whois jq nmap whatweb wpscan nuclei sslscan ffuf parallel python3; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $tool"
    else
        echo -e "  ${YELLOW}[ ]${NC} $tool (not installed)"
    fi
done

echo -e "\n${CYAN}Quick Start:${NC}"
echo "  1. Configure: nano ~/.ghostpress/config"
echo "  2. Run scan: ./ghostpress.sh -t example.com"
echo "  3. View help: ./ghostpress.sh --help"

echo -e "\n${YELLOW}Note:${NC} Get a free WPScan API token at: https://wpscan.com/api"
echo ""
