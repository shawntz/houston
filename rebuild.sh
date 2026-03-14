#!/usr/bin/env bash
set -euo pipefail

cd /opt/houston

echo "==> Pulling latest..."
git pull

echo "==> Building admin UI..."
cd admin-ui
npm run build
cd ..

echo "==> Building release binary..."
cargo build --release

echo "==> Deploying..."
sudo systemctl stop houston
sudo cp target/release/houston /usr/local/bin/houston
sudo systemctl start houston

echo "==> Done. Houston is running."
