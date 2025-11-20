import os
import subprocess
import sys
from pathlib import Path

def run_command(command, cwd=None):
    print(f"Running: {command}")
    try:
        subprocess.check_call(command, shell=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        sys.exit(1)

def main():
    base_dir = Path(__file__).parent
    
    # 1. Install Python dependencies
    print("Installing Python dependencies...")
    run_command(f"{sys.executable} -m pip install -r requirements.txt", cwd=base_dir)

    # 2. Check for Volatility 3
    vol_dir = base_dir / "volatility3"
    if not vol_dir.exists():
        print("Cloning Volatility 3...")
        run_command("git clone https://github.com/volatilityfoundation/volatility3.git", cwd=base_dir)
    else:
        print("Volatility 3 directory already exists. Skipping clone.")

    # 3. Install Volatility 3 dependencies
    if vol_dir.exists():
        print("Installing Volatility 3 dependencies...")
        # Volatility 3 usually has its own requirements, but we can just install the package in editable mode or standard
        # Let's try installing it as a package
        run_command(f"{sys.executable} -m pip install .", cwd=vol_dir)

    print("\nSetup complete!")
    print(f"Volatility 3 is located at: {vol_dir}")

if __name__ == "__main__":
    main()
