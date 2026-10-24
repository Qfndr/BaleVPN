#!/bin/sh
# Test build environment. Cargo outputs and downloads live in the mounted /build.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends pkg-config libssl-dev libglib2.0-dev libgtk-3-dev libsoup-3.0-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev libxdo-dev xvfb xauth dbus-x11 xdotool python3 ca-certificates
cargo fetch --locked --target x86_64-unknown-linux-gnu --manifest-path /src/bale-vpn-rust/Cargo.toml
touch /build/environment-ready
sleep infinity
