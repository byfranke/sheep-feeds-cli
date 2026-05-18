#!/bin/bash
set -eu

if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ]; then
    echo "Refusing to run: HOME is empty or '/' (would resolve to system paths)" >&2
    exit 1
fi

GITHUB_REPO="https://github.com/byfranke/sheep-feeds-cli"
GITHUB_RAW="https://raw.githubusercontent.com/byfranke/sheep-feeds-cli/main"
INSTALL_DIR="$HOME/.sheep-feeds-cli"
MIN_PYTHON_VERSION="3.7"

DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    echo "Either curl or wget is required but neither is installed" >&2
    exit 1
fi

download_file() {
    local url="$1"
    local output="$2"

    if [ "$DOWNLOADER" = "curl" ]; then
        if [ -n "$output" ]; then
            curl -fsSL -o "$output" "$url"
        else
            curl -fsSL "$url"
        fi
    else
        if [ -n "$output" ]; then
            wget -q -O "$output" "$url"
        else
            wget -q -O - "$url"
        fi
    fi
}

case "$(uname -s)" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "Windows is not fully supported. Use WSL or Git Bash." >&2
        OS="windows"
        ;;
    *)
        echo "Unsupported operating system: $(uname -s)" >&2
        exit 1
        ;;
esac

echo "================================="
echo "  Sheep Feeds CLI Installation"
echo "  OS: $OS | $(uname -m)"
echo "================================="
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python 3 is required but not installed" >&2
    echo "Please install Python $MIN_PYTHON_VERSION or higher" >&2
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[OK] Python $PYTHON_VERSION found"

if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
    echo "Installing pip..."
    python3 -m ensurepip --default-pip 2>/dev/null || {
        echo "[ERROR] pip is not installed and could not be installed automatically" >&2
        echo "Please install pip manually" >&2
        exit 1
    }
fi

echo "[OK] pip found"

if [ -f "requirements.txt" ] && [ -f "feeds-cli.py" ]; then
    WORK_DIR="$(pwd)"
else
    echo ""
    echo "Downloading Sheep Feeds CLI..."

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    WORK_DIR="$INSTALL_DIR"

    if command -v git >/dev/null 2>&1; then
        if [ -d "$INSTALL_DIR/.git" ]; then
            echo "Updating existing installation..."
            git fetch --quiet origin
            DEFAULT_BRANCH=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's@^origin/@@')
            DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
            git reset --hard --quiet "origin/$DEFAULT_BRANCH"
            git clean -fdq
        else
            rm -rf "$INSTALL_DIR"/* 2>/dev/null || true
            git clone --quiet "$GITHUB_REPO.git" "$INSTALL_DIR"
        fi
        echo "[OK] Repository cloned"
    else
        echo "Downloading files directly..."
        download_file "$GITHUB_RAW/feeds-cli.py" "feeds-cli.py"
        download_file "$GITHUB_RAW/setup.py" "setup.py"
        download_file "$GITHUB_RAW/requirements.txt" "requirements.txt"
        download_file "$GITHUB_RAW/uninstall.sh" "uninstall.sh" 2>/dev/null || true
        download_file "$GITHUB_RAW/VERSION" "VERSION" 2>/dev/null || true
        download_file "$GITHUB_RAW/LICENSE" "LICENSE" 2>/dev/null || true
        download_file "$GITHUB_RAW/README.md" "README.md" 2>/dev/null || true
        [ -f "uninstall.sh" ] && chmod +x uninstall.sh
        echo "[OK] Files downloaded"
    fi
fi

cd "$WORK_DIR"

echo ""
echo "Installing dependencies..."

install_deps() {
    local output
    output=$(pip3 install -r requirements.txt --user 2>&1) || true

    if echo "$output" | grep -q "Successfully installed\|already satisfied\|Requirement already"; then
        return 0
    fi

    if echo "$output" | grep -q "externally-managed-environment"; then
        echo ""
        echo "System uses externally managed Python (PEP 668)."
        echo "Trying: pip3 install --break-system-packages..."

        local out2
        out2=$(pip3 install -r requirements.txt --break-system-packages 2>&1)
        if [ $? -eq 0 ]; then
            return 0
        fi

        if echo "$out2" | grep -q "RECORD file not found.*installed by debian\|Cannot uninstall.*distutils"; then
            echo ""
            echo "Detected debian-managed Python package conflict."
            echo "Retrying with --ignore-installed (keeps the debian package)..."
            if pip3 install -r requirements.txt --break-system-packages --ignore-installed 2>&1; then
                return 0
            fi
        fi

        echo "$out2" | tail -5
    fi

    return 1
}

if ! install_deps; then
    echo "[ERROR] Failed to install dependencies" >&2
    echo ""
    echo "Please try one of these options manually:"
    echo ""
    echo "Option 1: Use a virtual environment (recommended):"
    echo "  cd $WORK_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    echo ""
    if [ "$OS" = "linux" ]; then
        echo "Option 2: Use system packages:"
        echo "  sudo apt install python3-rich python3-cryptography python3-keyring"
        echo ""
    fi
    echo "Option 3: Force install (may affect system):"
    echo "  sudo pip3 install -r requirements.txt --break-system-packages"
    echo ""
    exit 1
fi

echo "[OK] Dependencies installed"

chmod +x feeds-cli.py setup.py

echo ""
echo "Setting up command-line access..."

INSTALLED_PATH=""

if [ -w /usr/local/bin ]; then
    ln -sf "$WORK_DIR/feeds-cli.py" /usr/local/bin/sheep-feeds
    INSTALLED_PATH="/usr/local/bin/sheep-feeds"
    echo "[OK] Installed to /usr/local/bin/sheep-feeds"
elif command -v sudo >/dev/null 2>&1; then
    if sudo ln -sf "$WORK_DIR/feeds-cli.py" /usr/local/bin/sheep-feeds 2>/dev/null; then
        INSTALLED_PATH="/usr/local/bin/sheep-feeds"
        echo "[OK] Installed to /usr/local/bin/sheep-feeds"
    fi
fi

if [ -z "$INSTALLED_PATH" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$WORK_DIR/feeds-cli.py" "$HOME/.local/bin/sheep-feeds"
    INSTALLED_PATH="$HOME/.local/bin/sheep-feeds"
    echo "[OK] Installed to ~/.local/bin/sheep-feeds"

    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo ""
        echo "[INFO] Adding ~/.local/bin to PATH..."

        SHELL_RC=""
        if [ -n "${BASH_VERSION:-}" ]; then
            SHELL_RC="$HOME/.bashrc"
        elif [ -n "${ZSH_VERSION:-}" ]; then
            SHELL_RC="$HOME/.zshrc"
        elif [ -f "$HOME/.bashrc" ]; then
            SHELL_RC="$HOME/.bashrc"
        elif [ -f "$HOME/.zshrc" ]; then
            SHELL_RC="$HOME/.zshrc"
        fi

        if [ -n "$SHELL_RC" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            echo "[OK] Added to $SHELL_RC"
            echo "[INFO] Run 'source $SHELL_RC' or restart terminal to use 'sheep-feeds'"
        fi
    fi
fi

echo ""
echo "================================="
echo "  Installation Complete!"
echo "================================="
echo ""
echo "You can now use: sheep-feeds"
echo ""
echo "GitHub: $GITHUB_REPO"
echo "Get an API token: https://sheep.byfranke.com/pages/store"

echo ""
echo "Starting configuration..."
echo ""

cd "$WORK_DIR"
if [ -t 0 ]; then
    python3 setup.py
else
    python3 setup.py </dev/tty
fi
