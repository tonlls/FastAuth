"""
Installation script for fastapi-roles package development.
"""

import subprocess
import sys
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout:
            print(f"   Output: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print(f"   Error: {e.stderr.strip()}")
        return False


def main():
    """Main installation function."""
    print("🚀 FastAPI Roles Package Setup")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not Path("pyproject.toml").exists():
        print("❌ pyproject.toml not found. Please run this script from the project root.")
        sys.exit(1)
    
    # Install uv if not available
    print("\n📦 Setting up UV package manager...")
    if not run_command("uv --version", "Checking UV installation"):
        print("Installing UV...")
        if not run_command("pip install uv", "Installing UV"):
            print("❌ Failed to install UV. Please install it manually.")
            sys.exit(1)
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    if not run_command("uv pip install -e .", "Installing package in development mode"):
        print("❌ Failed to install package dependencies")
        sys.exit(1)
    
    # Install development dependencies
    print("\n🛠️ Installing development dependencies...")
    if not run_command("uv pip install -e .[dev]", "Installing development dependencies"):
        print("⚠️ Failed to install development dependencies (optional)")
    
    # Create demo database directory
    print("\n📁 Setting up demo environment...")
    Path("demo.db").touch()
    print("✅ Demo database file created")
    
    print("\n🎉 Setup completed successfully!")
    print("\n📖 Next steps:")
    print("   1. Run the demo: python main.py")
    print("   2. Check the docs: http://localhost:8000/docs")
    print("   3. Try the example: python examples/basic_app.py")
    print("\n💡 Demo users:")
    print("   - user@demo.com / password (user role)")
    print("   - admin@demo.com / admin (admin role)")


if __name__ == "__main__":
    main()
