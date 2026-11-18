#!/usr/bin/env bash
set -u

ROOT="$HOME/Downloads/CyberSwarm_merged_31"
PY="$ROOT/venv/bin/python"

export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH"

cd "$ROOT" || exit 1

if [[ ! -x "$PY" ]]; then
    echo "ERROR: Project virtual environment not found: $PY"
    exit 1
fi

echo "=== 1. Install Python packages ==="

"$PY" -m pip install arjun sslyze wafw00f impacket

echo
echo "=== 2. Install Go tools ==="

if command -v go >/dev/null 2>&1; then
    go install github.com/sensepost/gowitness@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/tomnomnom/waybackurls@latest
else
    echo "ERROR: Go is not installed."
fi

echo
echo "=== 3. Check SearchSploit ==="

if ! command -v searchsploit >/dev/null 2>&1; then
    echo "SearchSploit is not available on PATH."
    echo "Install it using the official Exploit Database instructions:"
    echo "https://github.com/offensive-security/exploitdb"
fi

echo
echo "=== 4. Check WPScan ==="

if ! command -v wpscan >/dev/null 2>&1; then
    if command -v gem >/dev/null 2>&1; then
        gem install wpscan --user-install
    else
        echo "RubyGems unavailable; WPScan skipped."
    fi
fi

echo
echo "=== 5. Check Impacket commands ==="

for name in GetNPUsers.py GetUserSPNs.py \
            impacket-GetNPUsers impacket-GetUserSPNs; do
    if command -v "$name" >/dev/null 2>&1; then
        echo "FOUND: $name -> $(command -v "$name")"
    fi
done

echo
echo "=== 6. Final CyberSwarm preflight ==="

hash -r
"$PY" -m tools.preflight

