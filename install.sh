#!/bin/sh
set -e

# Octane Accelerator installer for macOS and Linux
# Usage: curl -fsSL https://octane-fast.github.io/octane-accelerator/install.sh | sh

REPO="octane-fast/octane-accelerator"
INSTALL_DIR="$HOME/.octane"
BIN="$INSTALL_DIR/octane-accelerator"

echo "⚡ Octane Accelerator Installer"
echo ""

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64) PLATFORM="macos-arm64" ;;
      x86_64) PLATFORM="macos-x64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64) PLATFORM="linux-x64" ;;
      aarch64|arm64) PLATFORM="linux-arm64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/octane-accelerator-${PLATFORM}.tar.gz"

echo "  Platform: $PLATFORM"
echo "  Install to: $INSTALL_DIR"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and extract
echo "Downloading..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" | tar xz -C "$INSTALL_DIR"
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "$DOWNLOAD_URL" | tar xz -C "$INSTALL_DIR"
else
  echo "Error: curl or wget required"
  exit 1
fi

chmod +x "$BIN"
echo "  ✓ Binary installed"

# Set up auto-start
case "$OS" in
  Darwin)
    # macOS: LaunchAgent
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST="$PLIST_DIR/io.octane.accelerator.plist"
    mkdir -p "$PLIST_DIR"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.octane.accelerator</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>$INSTALL_DIR/accelerator.log</string>
</dict>
</plist>
EOF
    # Load the service
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "  ✓ Auto-start configured (LaunchAgent)"
    echo "  ✓ Service started"
    ;;
  Linux)
    # Linux: systemd user service
    SERVICE_DIR="$HOME/.config/systemd/user"
    SERVICE="$SERVICE_DIR/octane-accelerator.service"
    mkdir -p "$SERVICE_DIR"
    cat > "$SERVICE" <<EOF
[Unit]
Description=Octane Accelerator
After=network.target

[Service]
ExecStart=$BIN
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable octane-accelerator
    systemctl --user restart octane-accelerator
    echo "  ✓ Auto-start configured (systemd user service)"
    echo "  ✓ Service started"
    ;;
esac

echo ""
echo "✅ Octane Accelerator installed successfully!"
echo ""
echo "  The accelerator is now running in the background."
echo "  Your Octane wallet will automatically use it for faster proofs."
echo ""
echo "  To check status:  curl http://127.0.0.1:19876/health"
echo "  To view logs:     cat $INSTALL_DIR/accelerator.log"
echo "  To uninstall:     ~/.octane/uninstall.sh"
echo ""

# Create uninstall script
cat > "$INSTALL_DIR/uninstall.sh" <<'UNINSTALL'
#!/bin/sh
set -e
echo "Uninstalling Octane Accelerator..."
case "$(uname -s)" in
  Darwin)
    launchctl unload "$HOME/Library/LaunchAgents/io.octane.accelerator.plist" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/io.octane.accelerator.plist"
    ;;
  Linux)
    systemctl --user stop octane-accelerator 2>/dev/null || true
    systemctl --user disable octane-accelerator 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/octane-accelerator.service"
    systemctl --user daemon-reload
    ;;
esac
rm -rf "$HOME/.octane"
echo "✓ Uninstalled"
UNINSTALL
chmod +x "$INSTALL_DIR/uninstall.sh"
