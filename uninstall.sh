#!/bin/bash
set -eu

if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ]; then
    echo "Refusing to run: HOME is empty or '/' (would resolve to system paths)" >&2
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/.sheep-feeds-cli"
CONFIG_DIR="$HOME/.sheep-feeds-cli"
BACKUP_DIR="$HOME/.sheep-feeds-cli-backup-$(date +%Y%m%d-%H%M%S)"
SYSTEM_BIN="/usr/local/bin/sheep-feeds"
LOCAL_BIN="$HOME/.local/bin/sheep-feeds"
CURRENT_DIR="$(dirname "$(readlink -f "$0")")"

echo -e "${CYAN}================================="
echo "  Sheep Feeds CLI Uninstaller"
echo "=================================${NC}"
echo ""

print_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

check_installation() {
    local installed=false

    if [ -d "$INSTALL_DIR" ]; then
        print_info "Found installation directory: $INSTALL_DIR"
        installed=true
    fi

    if [ -f "$SYSTEM_BIN" ]; then
        print_info "Found system-wide installation: $SYSTEM_BIN"
        installed=true
    fi

    if [ -f "$LOCAL_BIN" ] || [ -L "$LOCAL_BIN" ]; then
        print_info "Found local bin installation: $LOCAL_BIN"
        installed=true
    fi

    if [ "$installed" = false ]; then
        print_warning "Sheep Feeds CLI installation not found"
        echo "Nothing to uninstall."
        exit 0
    fi
}

backup_config() {
    if [ -d "$CONFIG_DIR" ]; then
        echo ""
        if ask_yes_no "Do you want to backup your configuration files before uninstalling?"; then
            print_info "Creating backup at: $BACKUP_DIR"
            mkdir -p "$BACKUP_DIR"
            chmod 700 "$BACKUP_DIR"

            if [ -f "$CONFIG_DIR/config.ini" ]; then
                cp "$CONFIG_DIR/config.ini" "$BACKUP_DIR/" 2>/dev/null || true
                chmod 600 "$BACKUP_DIR/config.ini" 2>/dev/null || true
                print_success "Backed up config.ini"
            fi

            cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="$(dirname "$(readlink -f "$0")")"
CONFIG_DIR="$HOME/.sheep-feeds-cli"

echo "Restoring Sheep Feeds CLI configuration..."
mkdir -p "$CONFIG_DIR"
if [ -f "$BACKUP_DIR/config.ini" ]; then
    cp "$BACKUP_DIR/config.ini" "$CONFIG_DIR/"
    chmod 600 "$CONFIG_DIR/config.ini"
    echo "[OK] Restored config.ini"
fi
echo "Configuration restored successfully!"
EOF
            chmod 700 "$BACKUP_DIR/restore.sh"
            print_success "Backup completed (mode 0700 — owner only)"
            print_info "To restore configuration later, run: $BACKUP_DIR/restore.sh"
        fi
    fi
}

remove_symlinks() {
    local removed=false

    if [ -f "$SYSTEM_BIN" ]; then
        echo ""
        if ask_yes_no "Remove system-wide symlink from /usr/local/bin?"; then
            if sudo rm -f "$SYSTEM_BIN"; then
                print_success "Removed $SYSTEM_BIN"
                removed=true
            else
                print_error "Failed to remove $SYSTEM_BIN (may require sudo)"
            fi
        fi
    fi

    if [ -f "$LOCAL_BIN" ] || [ -L "$LOCAL_BIN" ]; then
        echo ""
        if ask_yes_no "Remove symlink from ~/.local/bin?"; then
            if rm -f "$LOCAL_BIN"; then
                print_success "Removed $LOCAL_BIN"
                removed=true
            else
                print_error "Failed to remove $LOCAL_BIN"
            fi
        fi
    fi

    if [ "$removed" = false ]; then
        print_info "No symlinks to remove"
    fi
}

remove_config_dir() {
    if [ -d "$CONFIG_DIR" ]; then
        echo ""
        if ask_yes_no "Remove configuration directory (~/.sheep-feeds-cli)?"; then
            if rm -rf "$CONFIG_DIR"; then
                print_success "Removed configuration directory"
            else
                print_error "Failed to remove configuration directory"
            fi
        fi
    fi
}

clear_session_cache() {
    local uid sid
    uid=$(id -u)
    sid=$(ps -o sid= -p $$ | tr -d ' ')
    local cache="/tmp/sheep-feeds-cli-sess-${uid}-${sid}"
    if [ -f "$cache" ]; then
        rm -f "$cache" && print_success "Cleared current terminal session cache"
    fi
}

remove_dependencies() {
    echo ""
    print_warning "The following Python packages were installed by Sheep Feeds CLI:"
    echo "  - requests"
    echo "  - rich"
    echo "  - cryptography"
    echo "  - keyring"
    echo "  - GitPython"
    echo ""
    print_warning "These packages might be used by other applications"

    if ask_yes_no "Do you want to uninstall these Python packages?"; then
        print_info "Attempting to uninstall Python packages..."
        for package in requests rich cryptography keyring GitPython; do
            echo -n "  Removing $package... "
            if pip3 uninstall -y "$package" 2>/dev/null || pip uninstall -y "$package" 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}SKIP${NC} (not installed or in use)"
            fi
        done
        print_success "Package removal completed"
    else
        print_info "Skipping Python package removal"
    fi
}

remove_local_files() {
    echo ""
    print_warning "This will remove Sheep Feeds CLI files from the current directory:"
    echo "  $CURRENT_DIR"
    echo ""
    echo "Files to be removed:"
    [ -f "$CURRENT_DIR/feeds-cli.py" ] && echo "  - feeds-cli.py"
    [ -f "$CURRENT_DIR/setup.py" ] && echo "  - setup.py"
    [ -f "$CURRENT_DIR/install.sh" ] && echo "  - install.sh"
    [ -f "$CURRENT_DIR/requirements.txt" ] && echo "  - requirements.txt"
    [ -f "$CURRENT_DIR/README.md" ] && echo "  - README.md"
    [ -f "$CURRENT_DIR/LICENSE" ] && echo "  - LICENSE"
    [ -f "$CURRENT_DIR/VERSION" ] && echo "  - VERSION"
    [ -f "$CURRENT_DIR/.gitignore" ] && echo "  - .gitignore"
    echo ""

    if ask_yes_no "Remove all Sheep Feeds CLI files from current directory?"; then
        rm -f "$CURRENT_DIR/feeds-cli.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/setup.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/install.sh" 2>/dev/null || true
        rm -f "$CURRENT_DIR/requirements.txt" 2>/dev/null || true
        rm -f "$CURRENT_DIR/README.md" 2>/dev/null || true
        rm -f "$CURRENT_DIR/LICENSE" 2>/dev/null || true
        rm -f "$CURRENT_DIR/VERSION" 2>/dev/null || true
        rm -f "$CURRENT_DIR/.gitignore" 2>/dev/null || true

        print_success "Removed local files"
        print_warning "Note: This uninstall script (uninstall.sh) will remain for your records"
        print_info "You can manually delete it if desired: rm $0"
    else
        print_info "Skipping local file removal"
    fi
}

cleanup_caches() {
    echo ""
    if ask_yes_no "Clean up Python caches and temporary files?"; then
        print_info "Cleaning pip cache..."
        pip3 cache purge 2>/dev/null || pip cache purge 2>/dev/null || true

        if [ -d "$CURRENT_DIR/__pycache__" ]; then
            rm -rf "$CURRENT_DIR/__pycache__"
            print_success "Removed Python cache directory"
        fi
        print_success "Cache cleanup completed"
    fi
}

main() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended unless removing system-wide installation"
    fi

    check_installation

    echo ""
    echo -e "${YELLOW}This will uninstall Sheep Feeds CLI from your system.${NC}"
    echo "You will be asked to confirm each step."
    echo ""

    if ! ask_yes_no "Do you want to continue with the uninstallation?"; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    backup_config
    clear_session_cache
    remove_symlinks
    remove_config_dir
    remove_dependencies
    remove_local_files
    cleanup_caches

    echo ""
    echo -e "${GREEN}================================="
    echo "  Uninstallation Complete"
    echo "=================================${NC}"
    echo ""

    if [ -d "$BACKUP_DIR" ]; then
        print_info "Your configuration was backed up to:"
        echo "  $BACKUP_DIR"
        echo ""
        print_info "To restore it later, run:"
        echo "  $BACKUP_DIR/restore.sh"
    fi

    echo ""
    print_success "Sheep Feeds CLI has been uninstalled"
    echo ""
    echo "Thank you for using Sheep Feeds CLI!"
    echo "For feedback or support: support@byfranke.com"
    echo ""
    echo "Want to come back? Reinstall any time:"
    echo "  curl -fsSL https://byfranke.com/ask-cli-install | bash"
    echo "Get an API token: https://sheep.byfranke.com/pages/store"
}

main "$@"
