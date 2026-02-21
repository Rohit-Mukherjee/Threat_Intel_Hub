#!/bin/bash
# Run the Threat Intelligence Hub Dashboard

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_STREAMLIT="$SCRIPT_DIR/venv/bin/streamlit"

# Check if virtual environment exists
if [ ! -f "$VENV_STREAMLIT" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run setup first: python3 setup.py"
    exit 1
fi

echo "🛡️  Starting Threat Intelligence Hub Dashboard..."
echo "📊 Dashboard will open at: http://localhost:8501"
"$VENV_STREAMLIT" run "$SCRIPT_DIR/dashboard/app.py"
