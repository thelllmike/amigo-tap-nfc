#!/bin/bash
# Build "AmigoTap NFC.app" and package it into AmigoTap-NFC.dmg
set -e
cd "$(dirname "$0")"

APP="AmigoTap NFC"
EXE="AmigoTapNFC"
BUNDLE="$APP.app"

if [ -f logo.png ]; then
  echo "==> generating app icon from logo.png"
  rm -rf AppIcon.iconset && mkdir AppIcon.iconset
  for s in 16 32 128 256 512; do
    sips -z $s $s logo.png --out "AppIcon.iconset/icon_${s}x${s}.png" >/dev/null 2>&1
    d=$((s*2))
    sips -z $d $d logo.png --out "AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null 2>&1
  done
  iconutil -c icns AppIcon.iconset -o AppIcon.icns
  rm -rf AppIcon.iconset
fi

echo "==> compiling C core"
cc -O2 -Wall -c nfccore.c -o nfccore.o

echo "==> compiling Swift GUI"
swiftc -O -o "$EXE" main.swift nfccore.o \
    -import-objc-header bridge.h \
    -framework AppKit -framework PCSC

echo "==> assembling app bundle"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
cp Info.plist "$BUNDLE/Contents/Info.plist"
cp "$EXE" "$BUNDLE/Contents/MacOS/$EXE"
[ -f AppIcon.icns ] && cp AppIcon.icns "$BUNDLE/Contents/Resources/AppIcon.icns" || true

echo "==> ad-hoc code signing"
codesign --force --deep --sign - "$BUNDLE"

echo "==> building DMG"
rm -f "AmigoTap-NFC.dmg"
rm -rf dmg_stage
mkdir dmg_stage
cp -R "$BUNDLE" dmg_stage/
ln -s /Applications dmg_stage/Applications
hdiutil create -volname "$APP" -srcfolder dmg_stage -ov -format UDZO "AmigoTap-NFC.dmg" >/dev/null
rm -rf dmg_stage

echo "==> done:"
echo "    $BUNDLE"
echo "    AmigoTap-NFC.dmg"
