#!/bin/bash
# Install gitleaks secret scanner locally (no sudo required)

set -e

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "Installing gitleaks to $INSTALL_DIR..."

# Download gitleaks
cd /tmp
wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz

# Extract and install
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
mv gitleaks "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/gitleaks"
rm gitleaks_8.18.1_linux_x64.tar.gz

echo "✅ Gitleaks installed successfully!"
echo ""
echo "Location: $INSTALL_DIR/gitleaks"
echo ""

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠️  Add $INSTALL_DIR to your PATH:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Or run directly: $INSTALL_DIR/gitleaks"
fi

"$INSTALL_DIR/gitleaks" version
