#!/bin/bash
# Double-click in Finder, or run: bash start-macos.command
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 18 or later is required, and it is not installed."
  echo
  echo "Install it from https://nodejs.org or run:  brew install node"
  echo "Then open this file again."
  read -r -p "Press Return to close." _
  exit 1
fi
exec node start.js "$@"
