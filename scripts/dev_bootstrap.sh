#!/bin/bash
# Development environment bootstrap

set -e

echo "========================================="
echo "Development Environment Setup"
echo "========================================="

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Create directories
echo "[*] Creating directory structure..."
mkdir -p outputs logs db models policy/candidate_templates

# Initialize database
echo "[*] Initializing database..."
python3 -c "from src.db.storage import init_db; init_db()"

# Create .env if not exists
if [ ! -f ".env" ]; then
    echo "[*] Creating .env from template..."
    cp .env.template .env
    echo "[!] Remember to add your GEMINI_API_KEY to .env"
fi

# Run smoke test
echo "[*] Running smoke test..."
python3 -c "
from src.config import load_config
from src.utils.logger import setup_logger
config = load_config()
setup_logger(config)
print('✓ Configuration loaded successfully')
"

echo ""
echo "========================================="
echo "Setup complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Add GEMINI_API_KEY to .env"
echo "  2. Run tests: python3 -m pytest tests/"
echo "  3. Try a scan: python3 src/main.py --target example.com --mode passive-only"
echo ""
