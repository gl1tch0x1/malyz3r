#!/bin/bash
# Automated recursive YARA scan script for Linux endpoints
# Usage: ./yara_scan.sh /path/to/scan /etc/yara-rules /var/log/yara_scan.log

SCAN_PATH=${1:-/}
RULES_DIR=${2:-/etc/yara-rules}
LOG_FILE=${3:-/var/log/yara_scan.log}
YARA_BIN=$(which yara)

if [ ! -x "$YARA_BIN" ]; then
  echo "[ERROR] YARA is not installed or not in PATH." >&2
  exit 1
fi

if [ ! -d "$RULES_DIR" ]; then
  echo "[ERROR] YARA rules directory not found: $RULES_DIR" >&2
  exit 1
fi

echo "[INFO] Starting YARA scan on $SCAN_PATH using rules in $RULES_DIR" | tee -a "$LOG_FILE"

find "$SCAN_PATH" -type f 2>/dev/null | while read -r file; do
  for rule in "$RULES_DIR"/*.yar; do
    result=$($YARA_BIN "$rule" "$file" 2>/dev/null)
    if [ ! -z "$result" ]; then
      echo "[ALERT] $(date +'%Y-%m-%d %H:%M:%S') Rule: $(basename "$rule") File: $file Result: $result" | tee -a "$LOG_FILE"
    fi
  done
done

echo "[INFO] YARA scan completed." | tee -a "$LOG_FILE"
