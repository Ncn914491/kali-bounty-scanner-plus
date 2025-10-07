#!/bin/bash

echo "========================================="
echo "Kali Bounty Scanner Plus - Installer"
echo "========================================="
echo ""
echo "⚠️  IMPORTANT REMINDERS:"
echo "  - Use only on authorized targets"
echo "  - Configure rate limits appropriately"
echo "  - Always verify scope before scanning"
echo ""

# Check if running on Kali or Debian-based system
if ! command -v apt-get &> /dev/null; then
    echo "⚠️  Warning: This installer is designed for Debian-based systems (Kali Linux)"
    echo "   You may need to manually install dependencies"
fi

# Check for required system tools
echo "[*] Checking for required system tools..."

REQUIRED_TOOLS=("subfinder" "httpx" "nuclei" "nmap" "nikto" "ffuf")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "⚠️  Missing tools: ${MISSING_TOOLS[*]}"
    echo ""
    echo "Install missing tools:"
    echo "  sudo apt update"
    echo "  sudo apt install -y nmap nikto"
    echo ""
    echo "  # Install Go tools:"
    echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "  go install github.com/ffuf/ffuf@latest"
    echo ""
else
    echo "✓ All required tools found"
fi

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "✗ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✓ Python $PYTHON_VERSION found"

# Create virtual environment
echo "[*] Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate venv and install dependencies
echo "[*] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ Python dependencies installed"
else
    echo "✗ Failed to install Python dependencies"
    exit 1
fi

# Create necessary directories
echo "[*] Creating directory structure..."
mkdir -p outputs logs db policy/candidate_templates src/reports/templates

# Initialize database
echo "[*] Initializing database..."
python3 -c "from src.db.storage import init_db; init_db()"
if [ $? -eq 0 ]; then
    echo "✓ Database initialized"
else
    echo "✗ Failed to initialize database"
fi

# Check for .env file
if [ ! -f ".env" ]; then
    echo ""
    echo "⚠️  No .env file found!"
    echo "   Copy .env.template to .env and add your Gemini API key:"
    echo "   cp .env.template .env"
    echo "   nano .env"
    echo ""
fi

echo ""
echo "========================================="
echo "Installation complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Configure .env with your Gemini API key"
echo "  2. Create a scope file for your target program"
echo "  3. Run: python3 src/main.py --target example.com --mode passive-only"
echo ""
echo "See README.md for detailed usage instructions"
echo ""
