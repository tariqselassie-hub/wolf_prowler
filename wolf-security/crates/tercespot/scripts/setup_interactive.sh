#!/bin/bash
# Setup script for Configurable Pulse Mechanism

ENV_FILE="/etc/tersec/sentinel.env"
SERVICE_FILE="/etc/systemd/system/sentinel.service"

echo "=== TersecPot Sentinel Setup ==="
echo "Select your Pulse Authentication Method:"
echo "1) USB Key (Physical File Token)"
echo "2) Web Log Pulse (Scan Nginx Logs)"
echo "3) TCP Pulse (Network Listener)"
read -p "Enter choice [1-3]: " choice

MODE=""
ARG=""

case $choice in
    1)
        MODE="USB"
        echo "You selected USB Mode."
        read -p "Enter the full path to the USB key file (e.g., /mnt/usb/pulse_key): " ARG
        if [ -z "$ARG" ]; then ARG="/mnt/usb/pulse_key"; fi
        ;;
    2)
        MODE="WEB"
        echo "You selected Web Log Pulse."
        read -p "Enter path to access.log (default: /var/log/nginx/access.log): " ARG
        if [ -z "$ARG" ]; then ARG="/var/log/nginx/access.log"; fi
        ;;
    3)
        MODE="TCP"
        echo "You selected TCP Pulse."
        read -p "Enter port to listen on (default: 9999): " ARG
        if [ -z "$ARG" ]; then ARG="9999"; fi
        ;;
    *)
        echo "Invalid choice. Defaulting to Web Log Pulse."
        MODE="WEB"
        ARG="/var/log/nginx/access.log"
        ;;
esac

echo "--- Configuration ---"
echo "Mode: $MODE"
echo "Arg:  $ARG"

# Create /etc/tersec directory if it doesn't exist
if [ ! -d "/etc/tersec" ]; then
    echo "Creating /etc/tersec..."
    # If not running as root, this might fail. In this simulated env we assume user handles privs.
    # We will just write locally for testing if /etc is blocked?
    # No, script assumes sudo execution.
    sudo mkdir -p /etc/tersec
fi

echo "Writing configuration to $ENV_FILE..."
# Write env file
sudo bash -c "cat > $ENV_FILE" <<EOF
TERSEC_PULSE_MODE=$MODE
TERSEC_PULSE_ARG=$ARG
TERSEC_POSTBOX=/tmp/postbox
EOF

echo "Configuration saved."
echo "Please reload systemd and restart sentinel:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl restart sentinel"
