#!/bin/bash
set -euo pipefail

# ============================================================
# Release build, sign, notarize, and package as DMG
# ============================================================
#
# Prerequisites:
#   1. Apple Developer account ($99/year) — developer.apple.com
#   2. In Xcode: Preferences > Accounts > add your Apple ID
#   3. Create a "Developer ID Application" certificate in
#      Certificates, Identifiers & Profiles
#   4. Set your Team ID below (or pass via environment variable)
#   5. Store notarization credentials in keychain:
#        xcrun notarytool store-credentials "notarize" \
#          --apple-id "you@example.com" \
#          --team-id "XXXXXXXXXX" \
#          --password "app-specific-password"
#
# Usage:
#   ./scripts/build-release.sh
#
# Environment overrides:
#   TEAM_ID=XXXXXXXXXX ./scripts/build-release.sh
#   KEYCHAIN_PROFILE=myprofile ./scripts/build-release.sh
#
# ============================================================

# --- Configuration ---
# Set these here or pass as environment variables
TEAM_ID="${TEAM_ID:-}"                          # Your 10-char Apple Team ID
KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-notarize}" # Keychain profile name (preferred)
# Fallback: plain credentials (less secure, use keychain profile instead)
APPLE_ID="${APPLE_ID:-}"
APP_PASSWORD="${APP_PASSWORD:-}"

APP_NAME="AdvancedPrivacyDashboard"
SCHEME="AdvancedPrivacyDashboard"
BUILD_DIR="build/release"
DMG_NAME="${APP_NAME}.dmg"

# Read version from Info.plist using PlistBuddy (works with XML plists)
PLIST_PATH="$(pwd)/AdvancedPrivacyDashboard/Info.plist"
if [ -f "$PLIST_PATH" ]; then
    VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST_PATH")
else
    VERSION="unknown"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Building ${APP_NAME} v${VERSION}"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# --- Validate config ---
if [ -z "$TEAM_ID" ]; then
    echo "ERROR: TEAM_ID is not set."
    echo ""
    echo "Setup steps:"
    echo "  1. Sign up at developer.apple.com (\$99/year)"
    echo "  2. Create a 'Developer ID Application' certificate"
    echo "  3. Find your Team ID at developer.apple.com/account"
    echo "  4. Store notarization credentials:"
    echo "       xcrun notarytool store-credentials \"notarize\" \\"
    echo "         --apple-id \"you@example.com\" \\"
    echo "         --team-id \"YOUR_TEAM_ID\" \\"
    echo "         --password \"app-specific-password\""
    echo "  5. Run: TEAM_ID=YOUR_TEAM_ID ./scripts/build-release.sh"
    echo ""
    exit 1
fi

# Verify Developer ID certificate exists
if ! security find-identity -v -p codesigning | grep -q "Developer ID Application"; then
    echo "ERROR: No 'Developer ID Application' certificate found in keychain."
    echo "Install one from developer.apple.com > Certificates, Identifiers & Profiles"
    exit 1
fi

echo "[1/6] Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# --- Regenerate project if xcodegen is available ---
if command -v xcodegen &> /dev/null; then
    echo "[2/6] Regenerating Xcode project with xcodegen..."
    xcodegen generate
else
    echo "[2/6] xcodegen not found, using existing project..."
fi

# --- Determine build method ---
PROJECT="${APP_NAME}.xcodeproj"
if [ -d "$PROJECT" ]; then
    echo "[3/6] Building Release (xcodeproj)..."
    xcodebuild \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -configuration Release \
        -derivedDataPath "$BUILD_DIR/derived" \
        DEVELOPMENT_TEAM="$TEAM_ID" \
        CODE_SIGN_IDENTITY="Developer ID Application" \
        CODE_SIGN_STYLE=Manual \
        clean build 2>&1 | tail -20
elif [ -f "Package.swift" ]; then
    echo "[3/6] Building Release (swift build)..."
    swift build -c release 2>&1 | tail -10
    echo "NOTE: SPM builds produce an executable, not a .app bundle."
    echo "      For full distribution with .app bundle, generate the xcodeproj first:"
    echo "      brew install xcodegen && xcodegen generate"
    exit 1
else
    echo "ERROR: No .xcodeproj or Package.swift found."
    exit 1
fi

APP_PATH="$BUILD_DIR/derived/Build/Products/Release/${APP_NAME}.app"

if [ ! -d "$APP_PATH" ]; then
    echo "ERROR: Build product not found at $APP_PATH"
    echo "Check build output above for errors."
    exit 1
fi

echo "    Built: $APP_PATH"

# --- Verify code signature ---
echo "[4/6] Verifying code signature..."
codesign --verify --deep --strict "$APP_PATH"
echo "    Signature valid."

# --- Notarize ---
echo "[5/6] Submitting for notarization..."
ZIP_PATH="$BUILD_DIR/${APP_NAME}.zip"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

# Prefer keychain profile (more secure), fall back to plain credentials
if xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" > /dev/null 2>&1; then
    xcrun notarytool submit "$ZIP_PATH" \
        --keychain-profile "$KEYCHAIN_PROFILE" \
        --wait
elif [ -n "$APPLE_ID" ] && [ -n "$APP_PASSWORD" ]; then
    xcrun notarytool submit "$ZIP_PATH" \
        --apple-id "$APPLE_ID" \
        --password "$APP_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait
else
    echo "ERROR: No valid notarization credentials found."
    echo "Set up keychain profile:"
    echo "  xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
    echo "    --apple-id \"you@example.com\" \\"
    echo "    --team-id \"$TEAM_ID\" \\"
    echo "    --password \"app-specific-password\""
    exit 1
fi

# Staple the notarization ticket
xcrun stapler staple "$APP_PATH"
echo "    Notarization complete."

# --- Create DMG ---
echo "[6/6] Creating DMG..."
DMG_PATH="$BUILD_DIR/${APP_NAME}-v${VERSION}.dmg"
rm -f "$DMG_PATH"

DMG_STAGING="$BUILD_DIR/dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
cp -R "$APP_PATH" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

hdiutil create \
    -volname "${APP_NAME} v${VERSION}" \
    -srcfolder "$DMG_STAGING" \
    -ov -format UDZO \
    "$DMG_PATH"

rm -rf "$DMG_STAGING"

# Notarize DMG
if xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" > /dev/null 2>&1; then
    xcrun notarytool submit "$DMG_PATH" \
        --keychain-profile "$KEYCHAIN_PROFILE" \
        --wait
else
    xcrun notarytool submit "$DMG_PATH" \
        --apple-id "$APPLE_ID" \
        --password "$APP_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait
fi

xcrun stapler staple "$DMG_PATH"

# Clean up zip
rm -f "$ZIP_PATH"

# --- Done ---
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  BUILD COMPLETE"
echo "╠══════════════════════════════════════════════════╣"
echo "║  App:     $APP_PATH"
echo "║  DMG:     $DMG_PATH"
echo "║  Version: $VERSION"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Next: Upload to GitHub Releases or your website."
