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
#   4. Set your Team ID below
#   5. Create an app-specific password at appleid.apple.com
#      for notarization
#
# Usage:
#   ./scripts/build-release.sh
#
# ============================================================

# --- Configuration (fill these in) ---
TEAM_ID=""                          # Your 10-char Apple Team ID
APPLE_ID=""                         # Your Apple ID email
APP_PASSWORD=""                     # App-specific password for notarytool
# Or use keychain profile:
# KEYCHAIN_PROFILE="notarize"      # Created via: xcrun notarytool store-credentials

APP_NAME="AdvancedPrivacyDashboard"
SCHEME="AdvancedPrivacyDashboard"
PROJECT="${APP_NAME}.xcodeproj"
BUILD_DIR="build/release"
DMG_NAME="${APP_NAME}.dmg"
VERSION=$(defaults read "$(pwd)/AdvancedPrivacyDashboard/Info.plist" CFBundleShortVersionString)

echo "=== Building ${APP_NAME} v${VERSION} ==="

# --- Validate config ---
if [ -z "$TEAM_ID" ]; then
    echo ""
    echo "ERROR: You need to configure this script first."
    echo ""
    echo "Steps:"
    echo "  1. Sign up at developer.apple.com (\$99/year)"
    echo "  2. Create a 'Developer ID Application' certificate"
    echo "  3. Edit this script and fill in TEAM_ID, APPLE_ID, APP_PASSWORD"
    echo "  4. Update DEVELOPMENT_TEAM in project.yml"
    echo "  5. Run: xcodegen generate"
    echo "  6. Re-run this script"
    echo ""
    exit 1
fi

# --- Clean and regenerate project ---
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
xcodegen generate

# --- Build release ---
echo "=== Building Release ==="
xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -derivedDataPath "$BUILD_DIR/derived" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    CODE_SIGN_IDENTITY="Developer ID Application" \
    CODE_SIGN_STYLE=Manual \
    clean build

APP_PATH="$BUILD_DIR/derived/Build/Products/Release/${APP_NAME}.app"

if [ ! -d "$APP_PATH" ]; then
    echo "ERROR: Build product not found at $APP_PATH"
    exit 1
fi

echo "=== Built: $APP_PATH ==="

# --- Notarize ---
echo "=== Submitting for notarization ==="
ZIP_PATH="$BUILD_DIR/${APP_NAME}.zip"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
    xcrun notarytool submit "$ZIP_PATH" \
        --keychain-profile "$KEYCHAIN_PROFILE" \
        --wait
else
    xcrun notarytool submit "$ZIP_PATH" \
        --apple-id "$APPLE_ID" \
        --password "$APP_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait
fi

# --- Staple ---
echo "=== Stapling notarization ticket ==="
xcrun stapler staple "$APP_PATH"

# --- Create DMG ---
echo "=== Creating DMG ==="
DMG_PATH="$BUILD_DIR/${DMG_NAME}"
rm -f "$DMG_PATH"

# Create a temporary folder for DMG contents
DMG_STAGING="$BUILD_DIR/dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
cp -R "$APP_PATH" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$DMG_STAGING" \
    -ov -format UDZO \
    "$DMG_PATH"

rm -rf "$DMG_STAGING"

# --- Notarize DMG too ---
echo "=== Notarizing DMG ==="
if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
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

# --- Done ---
echo ""
echo "=== DONE ==="
echo "DMG: $DMG_PATH"
echo "Version: $VERSION"
echo ""
echo "Upload to GitHub Releases or your website for distribution."
