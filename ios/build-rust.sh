#!/bin/bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$SRCROOT/.."
if [ "$CONFIGURATION" = Release ]; then
    profile=release
    cargo_profile=release
else
    profile=debug
    cargo_profile=dev
fi
# Xcode's SDK environment must not leak into Cargo's host-side build scripts.
unset SDKROOT
export IPHONEOS_DEPLOYMENT_TARGET="$IPHONEOS_DEPLOYMENT_TARGET"
export CARGO_TARGET_DIR="$PWD/target/ios"
libraries=()
architectures="$ARCHS"
if [[ "${ONLY_ACTIVE_ARCH:-NO}" = YES && " $architectures " = *" $NATIVE_ARCH_ACTUAL "* ]]; then
    architectures="$NATIVE_ARCH_ACTUAL"
fi
for architecture in $architectures; do
    case "$PLATFORM_NAME:$architecture" in
        iphoneos:arm64) rust_target=aarch64-apple-ios ;;
        iphonesimulator:arm64) rust_target=aarch64-apple-ios-sim ;;
        iphonesimulator:x86_64) rust_target=x86_64-apple-ios ;;
        *) echo "Unsupported Apple platform and architecture: $PLATFORM_NAME:$architecture" >&2; exit 1 ;;
    esac
    cargo build --locked -p sshportal-ios --target "$rust_target" --profile "$cargo_profile"
    libraries+=("$CARGO_TARGET_DIR/$rust_target/$profile/libsshportal_ios.a")
done
mkdir -p "$BUILT_PRODUCTS_DIR/rust"
xcrun lipo -create "${libraries[@]}" -output "$BUILT_PRODUCTS_DIR/rust/libsshportal_ios.a"
