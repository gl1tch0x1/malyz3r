
import os
import sys
import subprocess
from malware_scanner.cli import main

def auto_update():
    try:
        # Check if .git exists
        if not os.path.exists('.git'):
            print("[Auto-Update] Not a git repository. Skipping update check.")
            return
        # Fetch remote changes
        subprocess.run(["git", "fetch"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Check if local is behind remote
        local = subprocess.check_output(["git", "rev-parse", "@"], text=True).strip()
        remote = subprocess.check_output(["git", "rev-parse", "@{u}"], text=True).strip()
        if local != remote:
            print("[Auto-Update] Update available. Pulling latest changes...")
            subprocess.run(["git", "pull"], check=True)
            print("[Auto-Update] Update installed. Please re-run the tool.")
            sys.exit(0)
        else:
            print("[Auto-Update] Already up to date.")
    except Exception as e:
        print(f"[Auto-Update] Update check failed: {e}")

if __name__ == "__main__":
    auto_update()
    main()
