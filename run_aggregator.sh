#!/bin/bash
# Run the Threat Intelligence Hub aggregator

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"

# Check if virtual environment exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run setup first: python3 setup.py"
    exit 1
fi

echo "🛡️  Running Threat Intelligence Hub Aggregator..."
"$VENV_PYTHON" "$SCRIPT_DIR/aggregator.py"
