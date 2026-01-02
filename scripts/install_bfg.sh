#!/bin/bash
# Install BFG Repo-Cleaner

set -e

INSTALL_DIR="$HOME/.local/bin"
LIB_DIR="$HOME/.local/lib"
mkdir -p "$INSTALL_DIR"
mkdir -p "$LIB_DIR"

echo "Installing BFG Repo-Cleaner..."

# Download BFG JAR
wget -q https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar -O "$LIB_DIR/bfg.jar"

# Create wrapper script
cat > "$INSTALL_DIR/bfg" <<'EOF'
#!/bin/bash
java -jar "$HOME/.local/lib/bfg.jar" "$@"
EOF

chmod +x "$INSTALL_DIR/bfg"

echo "✅ BFG installed successfully!"
echo ""
echo "Location: $INSTALL_DIR/bfg"
echo "Usage: bfg --replace-text secrets.txt repo.git"
