#!/usr/bin/env bash
set -euo pipefail

# Create the venv only if it doesn't exist
if [ ! -d .venv ]; then
  "$(brew --prefix python@3.15)/bin/python3.15" -m venv .venv
fi

source .venv/bin/activate

# Install dependencies only if requirements.txt is new or has changed
STAMP=".venv/.requirements.sha256"
CURRENT_HASH="$(shasum -a 256 requirements.txt | cut -d' ' -f1)"

if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP")" != "$CURRENT_HASH" ]; then
  python -m pip install -r requirements.txt
  echo "$CURRENT_HASH" > "$STAMP"
fi

python main.py