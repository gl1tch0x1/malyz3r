"""Launch the scanner without modifying the checkout or fetching updates."""

from malware_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
