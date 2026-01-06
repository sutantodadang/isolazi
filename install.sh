#!/bin/bash

# isolazi Installation Script
# One-click install for macOS and Linux
# Downloads pre-built binaries from GitHub releases

set -e

# Configuration
REPO="sutantodadang/isolazi"
VERSION="${ISOLAZI_VERSION:-latest}"
INSTALL_DIR="${ISOLAZI_INSTALL_DIR:-$HOME/.isolazi}"
BIN_DIR="$INSTALL_DIR/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "  _           _           _ "
    echo " (_)___  ___ | | __ _ ___(_)"
    echo " | / __|/ _ \| |/ _\` |_  / |"
    echo " | \__ \ (_) | | (_| |/ /| |"
    echo " |_|___/\___/|_|\__,_/___|_|"
    echo -e "${NC}"
    echo "Container Runtime Installation Script"
    echo "======================================"
    echo ""
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS and Architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    
    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="macos"
            ;;
        mingw*|msys*|cygwin*)
            error "Please use install.ps1 for Windows installation"
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac
    
    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac
    
    PLATFORM="${OS}-${ARCH}"
    info "Detected platform: $PLATFORM"
}

# Detect shell
detect_shell() {
    SHELL_NAME=$(basename "$SHELL")
    info "Detected shell: $SHELL_NAME"
    
    case "$SHELL_NAME" in
        zsh)
            SHELL_RC="$HOME/.zshrc"
            SHELL_PROFILE="$HOME/.zprofile"
            ;;
        bash)
            if [[ "$OS" == "macos" ]]; then
                SHELL_RC="$HOME/.bash_profile"
            else
                SHELL_RC="$HOME/.bashrc"
            fi
            SHELL_PROFILE="$HOME/.profile"
            ;;
        fish)
            SHELL_RC="$HOME/.config/fish/config.fish"
            SHELL_PROFILE="$SHELL_RC"
            ;;
        *)
            warning "Unknown shell: $SHELL_NAME. Will try to add to .profile"
            SHELL_RC="$HOME/.profile"
            SHELL_PROFILE="$HOME/.profile"
            ;;
    esac
}

# Get the latest release version
get_latest_version() {
    if [[ "$VERSION" == "latest" ]]; then
        info "Fetching latest release version..."
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$VERSION" ]]; then
            error "Failed to fetch latest version. Please specify a version with ISOLAZI_VERSION=v0.1.11"
        fi
    fi
    info "Installing version: $VERSION"
}

# Download and install binary
download_binary() {
    local tmp_dir=$(mktemp -d)
    local archive=""
    local download_url=""
    
    # Try different URL patterns based on common release naming conventions
    local url_patterns=(
        "https://github.com/${REPO}/releases/download/${VERSION}/isolazi-${PLATFORM}.tar.gz"
        "https://github.com/${REPO}/releases/download/${VERSION}/isolazi-${OS}-${ARCH}.tar.gz"
        "https://github.com/${REPO}/releases/download/${VERSION}/isolazi_${PLATFORM}.tar.gz"
        "https://github.com/${REPO}/releases/download/${VERSION}/isolazi-${PLATFORM}.zip"
        "https://github.com/${REPO}/releases/download/${VERSION}/isolazi-${OS}-${ARCH}.zip"
    )
    
    local downloaded=false
    
    for url in "${url_patterns[@]}"; do
        info "Trying: $url"
        
        if [[ "$url" == *.zip ]]; then
            archive="$tmp_dir/isolazi.zip"
        else
            archive="$tmp_dir/isolazi.tar.gz"
        fi
        
        if curl -fsSL "$url" -o "$archive" 2>/dev/null; then
            download_url="$url"
            downloaded=true
            success "Downloaded from: $url"
            break
        fi
    done
    
    if [[ "$downloaded" == false ]]; then
        rm -rf "$tmp_dir"
        error "Failed to download binary. Please check releases at: https://github.com/${REPO}/releases"
    fi
    
    info "Extracting archive..."
    mkdir -p "$BIN_DIR"
    
    if [[ "$archive" == *.zip ]]; then
        unzip -q "$archive" -d "$tmp_dir/extracted"
    else
        mkdir -p "$tmp_dir/extracted"
        tar -xzf "$archive" -C "$tmp_dir/extracted"
    fi
    
    # Find the binary - check various possible locations
    local binary=""
    
    # Look for the binary in common locations
    for possible_binary in \
        "$tmp_dir/extracted/isolazi" \
        "$tmp_dir/extracted/bin/isolazi" \
        "$tmp_dir/extracted/isolazi-${PLATFORM}/isolazi" \
        "$tmp_dir/extracted/isolazi-${PLATFORM}/bin/isolazi" \
        $(find "$tmp_dir/extracted" -name "isolazi" -type f 2>/dev/null | head -1)
    do
        if [[ -f "$possible_binary" ]]; then
            binary="$possible_binary"
            break
        fi
    done
    
    if [[ -z "$binary" ]]; then
        # List contents for debugging
        info "Archive contents:"
        find "$tmp_dir/extracted" -type f 2>/dev/null || true
        rm -rf "$tmp_dir"
        error "Could not find isolazi binary in the downloaded archive"
    fi
    
    cp "$binary" "$BIN_DIR/isolazi"
    chmod +x "$BIN_DIR/isolazi"
    
    # Also copy benchmark binary if present
    local bench_binary=$(find "$tmp_dir/extracted" -name "isolazi-bench" -type f 2>/dev/null | head -1)
    if [[ -n "$bench_binary" ]] && [[ -f "$bench_binary" ]]; then
        cp "$bench_binary" "$BIN_DIR/isolazi-bench"
        chmod +x "$BIN_DIR/isolazi-bench"
        info "Also installed isolazi-bench"
    fi
    
    # Cleanup
    rm -rf "$tmp_dir"
    
    success "Binary installed to $BIN_DIR/isolazi"
}

# Add to PATH
add_to_path() {
    local path_export="export PATH=\"\$PATH:$BIN_DIR\""
    local fish_path="set -gx PATH \$PATH $BIN_DIR"
    
    # Check if already in PATH
    if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
        info "Directory already in PATH"
        return 0
    fi
    
    info "Adding $BIN_DIR to PATH..."
    
    if [[ "$SHELL_NAME" == "fish" ]]; then
        # Fish shell configuration
        mkdir -p "$(dirname "$SHELL_RC")"
        if ! grep -q "$BIN_DIR" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# isolazi" >> "$SHELL_RC"
            echo "$fish_path" >> "$SHELL_RC"
            success "Added to $SHELL_RC"
        else
            info "Path already configured in $SHELL_RC"
        fi
    else
        # Bash/Zsh configuration
        if [[ -f "$SHELL_RC" ]]; then
            if ! grep -q "$BIN_DIR" "$SHELL_RC" 2>/dev/null; then
                echo "" >> "$SHELL_RC"
                echo "# isolazi" >> "$SHELL_RC"
                echo "$path_export" >> "$SHELL_RC"
                success "Added to $SHELL_RC"
            else
                info "Path already configured in $SHELL_RC"
            fi
        else
            # Create shell rc file
            echo "# isolazi" > "$SHELL_RC"
            echo "$path_export" >> "$SHELL_RC"
            success "Created $SHELL_RC with PATH configuration"
        fi
        
        # Also add to profile for login shells
        if [[ -f "$SHELL_PROFILE" ]] && [[ "$SHELL_PROFILE" != "$SHELL_RC" ]]; then
            if ! grep -q "$BIN_DIR" "$SHELL_PROFILE" 2>/dev/null; then
                echo "" >> "$SHELL_PROFILE"
                echo "# isolazi" >> "$SHELL_PROFILE"
                echo "$path_export" >> "$SHELL_PROFILE"
                info "Also added to $SHELL_PROFILE"
            fi
        fi
    fi
    
    # Export for current session
    export PATH="$PATH:$BIN_DIR"
}

# Verify installation
verify_installation() {
    info "Verifying installation..."
    
    if [[ -x "$BIN_DIR/isolazi" ]]; then
        success "isolazi installed successfully!"
        echo ""
        echo -e "${GREEN}Installation complete!${NC}"
        echo ""
        echo "To start using isolazi, either:"
        echo "  1. Restart your terminal, or"
        echo "  2. Run: source $SHELL_RC"
        echo ""
        echo "Then try: isolazi --help"
        echo ""
        
        # Show version
        "$BIN_DIR/isolazi" --version 2>/dev/null || true
    else
        error "Installation verification failed"
    fi
}

# Uninstall function
uninstall() {
    warning "Uninstalling isolazi..."
    
    # Remove binary directory
    if [[ -d "$BIN_DIR" ]]; then
        rm -rf "$BIN_DIR"
        info "Removed $BIN_DIR"
    fi
    
    # Remove install directory if empty
    if [[ -d "$INSTALL_DIR" ]]; then
        rmdir "$INSTALL_DIR" 2>/dev/null || true
    fi
    
    # Remove from shell rc (best effort)
    for rc_file in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zprofile"; do
        if [[ -f "$rc_file" ]]; then
            # Remove isolazi related lines
            if [[ "$OS" == "macos" ]]; then
                sed -i '' '/# isolazi/d' "$rc_file" 2>/dev/null || true
                sed -i '' "/.isolazi\/bin/d" "$rc_file" 2>/dev/null || true
            else
                sed -i '/# isolazi/d' "$rc_file" 2>/dev/null || true
                sed -i "/.isolazi\/bin/d" "$rc_file" 2>/dev/null || true
            fi
        fi
    done
    
    # Remove fish config
    if [[ -f "$HOME/.config/fish/config.fish" ]]; then
        if [[ "$OS" == "macos" ]]; then
            sed -i '' '/isolazi/d' "$HOME/.config/fish/config.fish" 2>/dev/null || true
        else
            sed -i '/isolazi/d' "$HOME/.config/fish/config.fish" 2>/dev/null || true
        fi
    fi
    
    success "isolazi has been uninstalled"
}

# Main installation flow
main() {
    print_banner
    
    # Handle uninstall flag
    if [[ "$1" == "--uninstall" ]] || [[ "$1" == "-u" ]]; then
        detect_platform
        uninstall
        exit 0
    fi
    
    # Handle help flag
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -h, --help       Show this help message"
        echo "  -u, --uninstall  Uninstall isolazi"
        echo ""
        echo "Environment variables:"
        echo "  ISOLAZI_VERSION      Version to install (default: latest)"
        echo "  ISOLAZI_INSTALL_DIR  Custom installation directory (default: ~/.isolazi)"
        echo ""
        echo "Examples:"
        echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash"
        echo "  ISOLAZI_VERSION=v0.1.11 ./install.sh"
        echo ""
        exit 0
    fi
    
    detect_platform
    detect_shell
    get_latest_version
    download_binary
    add_to_path
    verify_installation
}

main "$@"
