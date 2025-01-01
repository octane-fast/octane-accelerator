#!/bin/bash
set -e

# Creates "Octane Accelerator.app" (menu bar app) and packages it into a DMG
# Usage: ./scripts/create-dmg.sh <server-binary-path> <arch>
# Example: ./scripts/create-dmg.sh ./octane-accelerator arm64

BINARY="$1"
ARCH="${2:-arm64}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"  # defaults to ad-hoc (-), set env var for real signing
APP_NAME="Octane Accelerator"
DMG_NAME="octane-accelerator-macos-${ARCH}.dmg"

if [ ! -f "$BINARY" ]; then
  echo "Error: server binary not found at $BINARY"
  exit 1
fi

# Clean previous builds
rm -rf "${APP_NAME}.app" "$DMG_NAME" dmg-staging

# Create .icns from PNG if not already present
if [ ! -f res/icon.icns ]; then
  echo "Creating .icns..."
  mkdir -p icon.iconset
  sips -z 16 16   icon128.png --out icon.iconset/icon_16x16.png      2>/dev/null
  sips -z 32 32   icon128.png --out icon.iconset/icon_16x16@2x.png   2>/dev/null
  sips -z 32 32   icon128.png --out icon.iconset/icon_32x32.png      2>/dev/null
  sips -z 64 64   icon128.png --out icon.iconset/icon_32x32@2x.png   2>/dev/null
  sips -z 128 128 icon128.png --out icon.iconset/icon_128x128.png    2>/dev/null
  cp icon128.png icon.iconset/icon_128x128@2x.png
  iconutil -c icns icon.iconset -o res/icon.icns
  rm -rf icon.iconset
fi

# Use pre-rendered menu bar template icons (transparent bg, black flame)
MENU_ICON_1X="tray/MenuIcon.png"
MENU_ICON_2X="tray/MenuIcon@2x.png"

# Compile the tray app
echo "Compiling tray app..."
TRAY_FLAGS="-framework Cocoa -framework ServiceManagement -framework UniformTypeIdentifiers -fobjc-arc -O2"
if [ "$ARCH" = "arm64" ]; then
  clang $TRAY_FLAGS -target arm64-apple-macos12 -o tray_app tray/main.m
elif [ "$ARCH" = "x64" ]; then
  clang $TRAY_FLAGS -target x86_64-apple-macos12 -o tray_app tray/main.m
else
  clang $TRAY_FLAGS -o tray_app tray/main.m
fi

# Create .app bundle
APP="${APP_NAME}.app"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"

# Copy binaries
cp tray_app "$APP/Contents/MacOS/OctaneAccelerator"
chmod +x "$APP/Contents/MacOS/OctaneAccelerator"
cp "$BINARY" "$APP/Contents/MacOS/octane-accelerator"
chmod +x "$APP/Contents/MacOS/octane-accelerator"
rm -f tray_app

# Copy resources
cp res/icon.icns "$APP/Contents/Resources/AppIcon.icns"
cp "$MENU_ICON_1X" "$APP/Contents/Resources/MenuIcon.png"
cp "$MENU_ICON_2X" "$APP/Contents/Resources/MenuIcon@2x.png"

# Create Info.plist
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>Octane Accelerator</string>
  <key>CFBundleDisplayName</key>
  <string>Octane Accelerator</string>
  <key>CFBundleIdentifier</key>
  <string>io.octane.accelerator</string>
  <key>CFBundleVersion</key>
  <string>0.4.23</string>
  <key>CFBundleShortVersionString</key>
  <string>0.4.23</string>
  <key>CFBundleExecutable</key>
  <string>OctaneAccelerator</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

# Codesign (with hardened runtime for notarization)
if [ -n "$SIGN_IDENTITY" ]; then
  echo "Codesigning with: $SIGN_IDENTITY"
  codesign --force --deep --options runtime --timestamp -s "$SIGN_IDENTITY" "$APP/Contents/MacOS/octane-accelerator"
  codesign --force --deep --options runtime --timestamp -s "$SIGN_IDENTITY" "$APP"
else
  echo "Codesigning ad-hoc (no SIGN_IDENTITY set)"
  codesign --force --deep -s - "$APP"
fi

# Create DMG with Applications symlink
echo "Creating DMG..."
mkdir -p dmg-staging
cp -R "$APP" dmg-staging/
ln -s /Applications dmg-staging/Applications

hdiutil create -volname "Octane Accelerator" \
  -srcfolder dmg-staging \
  -ov -format UDZO \
  "$DMG_NAME"

# Sign the DMG itself (required for notarization)
if [ "$SIGN_IDENTITY" != "-" ]; then
  echo "Signing DMG..."
  codesign --force --timestamp -s "$SIGN_IDENTITY" "$DMG_NAME"
fi

rm -rf dmg-staging "${APP_NAME}.app"

echo "✓ Created $DMG_NAME"
echo "  User drags 'Octane Accelerator' to Applications, opens it → menu bar icon appears"
