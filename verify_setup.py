#!/usr/bin/env python3
"""
SpyNet Setup Verification Script
Verifies that all components are properly installed and configured
"""
import os
import sys
import subprocess
from pathlib import Path


def check_python_packages():
    """Check if all required Python packages are installed"""
    print("🔍 Checking Python packages...")
    
    required_packages = [
        'scapy', 'fastapi', 'psycopg2', 'sklearn', 
        'sqlalchemy', 'uvicorn', 'pydantic', 'pydantic_settings'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing_packages.append(package)
    
    return len(missing_packages) == 0


def check_node_setup():
    """Check if Node.js and frontend dependencies are set up"""
    print("\n🔍 Checking Node.js setup...")
    
    frontend_path = Path("frontend")
    if not frontend_path.exists():
        print("  ❌ Frontend directory not found")
        return False
    
    package_json = frontend_path / "package.json"
    if not package_json.exists():
        print("  ❌ package.json not found")
        return False
    
    node_modules = frontend_path / "node_modules"
    if not node_modules.exists():
        print("  ❌ node_modules not found - run 'npm install' in frontend directory")
        return False
    
    print("  ✅ Frontend setup complete")
    return True


def check_config_files():
    """Check if configuration files exist"""
    print("\n🔍 Checking configuration files...")
    
    config_files = [
        "backend/.env.example",
        "backend/config.py",
        "frontend/.env.local.example",
        "frontend/src/config/api.ts"
    ]
    
    all_exist = True
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"  ✅ {config_file}")
        else:
            print(f"  ❌ {config_file}")
            all_exist = False
    
    return all_exist


def check_project_structure():
    """Check if project structure is correct"""
    print("\n🔍 Checking project structure...")
    
    required_dirs = [
        "backend",
        "frontend",
        "backend/venv"
    ]
    
    required_files = [
        "README.md",
        "backend/main.py",
        "backend/requirements.txt",
        "frontend/package.json"
    ]
    
    all_good = True
    
    for directory in required_dirs:
        if Path(directory).exists():
            print(f"  ✅ {directory}/")
        else:
            print(f"  ❌ {directory}/")
            all_good = False
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path}")
            all_good = False
    
    return all_good


def main():
    """Main verification function"""
    print("🚀 SpyNet Setup Verification")
    print("=" * 40)
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    checks = [
        ("Project Structure", check_project_structure),
        ("Configuration Files", check_config_files),
        ("Python Packages", check_python_packages),
        ("Node.js Setup", check_node_setup)
    ]
    
    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"  ❌ Error during {check_name}: {e}")
            results.append((check_name, False))
    
    print("\n" + "=" * 40)
    print("📋 VERIFICATION SUMMARY")
    print("=" * 40)
    
    all_passed = True
    for check_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {check_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 40)
    if all_passed:
        print("🎉 All checks passed! SpyNet is ready for development.")
        print("\nNext steps:")
        print("1. Copy backend/.env.example to backend/.env and configure your database")
        print("2. Copy frontend/.env.local.example to frontend/.env.local")
        print("3. Set up your NeonDB database (see backend/database_setup.md)")
        print("4. Start the backend: python backend/main.py")
        print("5. Start the frontend: cd frontend && npm run dev")
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()