#!/usr/bin/env bash
set -uo pipefail

# CyberSwarm external tool installer for Ubuntu.
# Run from the project directory.
# Use only on systems you own or are authorized to assess.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/venv"
TOOLS="$ROOT/tools"
LOCAL_BIN="$HOME/.local/bin"
GO_BIN="$(go env GOPATH 2>/dev/null)/bin"

mkdir -p "$TOOLS" "$LOCAL_BIN"

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "ERROR: Virtual environment not found: $VENV"
    echo "Create it first, then install your project's Python dependencies."
    exit 1
fi

PY="$VENV/bin/python"
PIP="$PY -m pip"

echo "=================================================="
echo " CyberSwarm external tool installer"
echo " Project: $ROOT"
echo " Python:  $PY"
echo "=================================================="

export DEBIAN_FRONTEND=noninteractive

echo
echo "[1/7] Installing Ubuntu system dependencies..."

sudo apt-get update

sudo apt-get install -y \
    ca-certificates curl wget git \
    build-essential pkg-config \
    python3-dev python3-venv \
    golang-go cargo rustc \
    ruby-full \
    nmap hydra nikto sqlmap whatweb \
    testssl.sh \
    dnsutils whois \
    libpcap-dev libssl-dev \
    libffi-dev libxml2-dev libxslt1-dev \
    zlib1g-dev jq unzip \
    || echo "[WARN] Some system packages could not be installed."

echo
echo "[2/7] Preparing Python packages..."

"$PY" -m pip install --upgrade pip setuptools wheel \
    || echo "[WARN] Could not upgrade pip."

"$PY" -m pip install \
    dnspython \
    impacket \
    arjun \
    sslyze \
    wafw00f \
    corsy \
    commix \
    jwt-tool \
    || echo "[WARN] Some Python packages failed. Check compatibility with Python."

echo
echo "[3/7] Installing Go-based security tools..."

export PATH="$LOCAL_BIN:$HOME/go/bin:$PATH"

if ! command -v go >/dev/null 2>&1; then
    echo "[WARN] Go is unavailable; skipping Go-based tools."
else
    export GOBIN="$HOME/go/bin"
    mkdir -p "$GOBIN"

    install_go_tool() {
        local package="$1"
        echo "Installing $package"
        go install "$package" || echo "[WARN] Failed: $package"
    }

    install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    install_go_tool github.com/projectdiscovery/httpx/cmd/httpx@latest
    install_go_tool github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    install_go_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    install_go_tool github.com/projectdiscovery/katana/cmd/katana@latest
    install_go_tool github.com/ffuf/ffuf/v2@latest
    install_go_tool github.com/hahwul/dalfox/v2@latest
    install_go_tool github.com/lc/gau/v2/cmd/gau@latest
    install_go_tool github.com/haccer/subjack@latest
    install_go_tool github.com/owasp-amass/amass/v5/cmd/amass@main
fi

echo
echo "[4/7] Installing Rust-based content discovery tool..."

if command -v cargo >/dev/null 2>&1; then
    cargo install feroxbuster \
        || echo "[WARN] feroxbuster installation failed."
fi

echo
echo "[5/7] Installing standalone Python security tools..."

clone_tool() {
    local name="$1"
    local repo="$2"
    local destination="$TOOLS/$name"

    if [[ -d "$destination/.git" ]]; then
        echo "$name already cloned."
    else
        git clone --depth 1 "$repo" "$destination" \
            || {
                echo "[WARN] Could not clone $name"
                return 0
            }
    fi
}

clone_tool jwt_tool https://github.com/ticarpi/jwt_tool.git
clone_tool LinkFinder https://github.com/GerbenJavado/LinkFinder.git
clone_tool Corsy https://github.com/s0md3v/Corsy.git
clone_tool commix https://github.com/commixproject/commix.git

# Make common standalone scripts discoverable by CyberSwarm.
# These wrappers use the project's virtual environment.
make_python_wrapper() {
    local name="$1"
    local script="$2"
    local wrapper="$LOCAL_BIN/$name"

    if [[ -f "$script" ]]; then
        cat > "$wrapper" <<EOF
#!/usr/bin/env bash
exec "$PY" "$script" "\$@"
EOF
        chmod +x "$wrapper"
        echo "Created wrapper: $wrapper"
    fi
}

make_python_wrapper jwt_tool "$TOOLS/jwt_tool/jwt_tool.py"
make_python_wrapper linkfinder "$TOOLS/LinkFinder/linkfinder.py"
make_python_wrapper corsy "$TOOLS/Corsy/corsy.py"
make_python_wrapper commix "$TOOLS/commix/commix.py"

echo
echo "[6/7] Installing WPScan and additional Python dependencies..."

if command -v gem >/dev/null 2>&1; then
    gem install wpscan --user-install \
        || echo "[WARN] WPScan installation failed."
fi

"$PY" -m pip install \
    requests beautifulsoup4 lxml \
    PyYAML rich httpx \
    || echo "[WARN] Some supporting Python packages failed."

echo
echo "[7/7] Updating PATH and running preflight..."

# Persist the relevant executable directories for future terminals.
PROFILE="$HOME/.profile"

for line in \
    'export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH"'
do
    grep -Fqx "$line" "$PROFILE" 2>/dev/null ||
        echo "$line" >> "$PROFILE"
done

export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH"

echo
echo "Installed tool versions where available:"
for binary in \
    nmap hydra nikto sqlmap whatweb \
    amass arjun commix corsy dalfox \
    feroxbuster ffuf gau gowitness httpx \
    jwt_tool katana naabu nuclei searchsploit \
    sqlmap sslyze subfinder subjack testssl \
    wafw00f waybackurls wpscan \
    GetNPUsers.py GetUserSPNs.py
do
    if command -v "$binary" >/dev/null 2>&1; then
        printf '  OK      %s -> %s\n' "$binary" "$(command -v "$binary")"
    else
        printf '  MISSING %s\n' "$binary"
    fi
done

echo
echo "Running CyberSwarm preflight..."

cd "$ROOT"

if "$PY" -m tools.preflight; then
    echo
    echo "Preflight completed."
else
    echo
    echo "[WARN] Preflight reported missing tools or errors."
fi

echo
echo "=================================================="
echo "Installation attempt complete."
echo "Review warnings and rerun preflight if necessary."
echo "=================================================="
