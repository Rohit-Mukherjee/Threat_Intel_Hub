#!/usr/bin/env python3
"""
Simple setup script for Threat Intelligence Hub
Automatically creates virtual environment and installs dependencies
"""

import subprocess
import sys
import os
import venv

def main():
    print("=" * 60)
    print("🛡️  Threat Intelligence Hub - Setup")
    print("=" * 60)
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(script_dir, "venv")
    
    # Create virtual environment if it doesn't exist
    if not os.path.exists(venv_dir):
        print("\n📦 Creating virtual environment...")
        venv.create(venv_dir, with_pip=True)
        print("✓ Virtual environment created at: venv/")
    else:
        print("✓ Virtual environment already exists")
    
    # Determine the correct pip path based on OS
    if sys.platform == "win32":
        pip_path = os.path.join(venv_dir, "Scripts", "pip")
        python_path = os.path.join(venv_dir, "Scripts", "python")
    else:
        pip_path = os.path.join(venv_dir, "bin", "pip")
        python_path = os.path.join(venv_dir, "bin", "python")
    
    # Upgrade pip
    print("\n⬆️  Upgrading pip...")
    subprocess.run([python_path, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    
    # Install dependencies
    print("\n📥 Installing dependencies...")
    requirements_path = os.path.join(script_dir, "requirements.txt")
    subprocess.run([pip_path, "install", "-r", requirements_path], check=True)
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(script_dir, "data")
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        print("✓ Created data directory")
    
    # Create logs directory
    logs_dir = os.path.join(script_dir, "logs")
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
        print("✓ Created logs directory")
    
    print("\n" + "=" * 60)
    print("✅ Setup complete!")
    print("=" * 60)
    print("\n📝 Next steps:")
    print("   1. Run the aggregator: python aggregator.py")
    print("   2. Launch the dashboard: streamlit run dashboard/app.py")
    print("\n   Or use the run scripts:")
    if sys.platform == "win32":
        print("   - .\\run_aggregator.bat")
        print("   - .\\run_dashboard.bat")
    else:
        print("   - ./run_aggregator.sh")
        print("   - ./run_dashboard.sh")
    print("\n")

if __name__ == "__main__":
    main()
