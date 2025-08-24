#!/usr/bin/env python3
"""
Startup script for the Advanced Port Scanner & Vulnerability Detector Backend
"""

import sys
import os
import subprocess
import platform

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_nmap_installation():
    """Check if nmap is installed and accessible"""
    try:
        # Try to run nmap --version
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ nmap is installed and accessible")
            return True
        else:
            print("❌ nmap is installed but not working properly")
            return False
    except FileNotFoundError:
        print("❌ nmap is not installed")
        print("Please install nmap:")
        if platform.system() == "Windows":
            print("  - Download from: https://nmap.org/download.html")
            print("  - Or use: winget install nmap")
        elif platform.system() == "Darwin":  # macOS
            print("  - Use: brew install nmap")
        else:  # Linux
            print("  - Use: sudo apt-get install nmap")
        return False
    except Exception as e:
        print(f"❌ Error checking nmap: {e}")
        return False

def install_dependencies():
    """Install Python dependencies"""
    try:
        print("📦 Installing Python dependencies...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def start_server():
    """Start the FastAPI server"""
    try:
        print("🚀 Starting FastAPI server...")
        print("📡 Server will be available at: http://localhost:8000")
        print("📚 API documentation at: http://localhost:8000/docs")
        print("🔍 Health check at: http://localhost:8000/health")
        print("\nPress Ctrl+C to stop the server\n")
        
        # Start the server
        subprocess.run([
            sys.executable, '-m', 'uvicorn', 
            'main:app', 
            '--host', '0.0.0.0', 
            '--port', '8000', 
            '--reload'
        ])
        
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

def main():
    """Main startup function"""
    print("🔒 Advanced Port Scanner & Vulnerability Detector")
    print("=" * 55)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check nmap installation
    if not check_nmap_installation():
        print("\n⚠️  nmap is required for full functionality")
        print("The application will use basic socket scanning as fallback")
        print("Continue anyway? (y/N): ", end="")
        response = input().strip().lower()
        if response not in ['y', 'yes']:
            print("Exiting...")
            sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Start server
    start_server()

if __name__ == "__main__":
    main()
