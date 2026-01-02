#!/usr/bin/env python3
import os
import shutil
import subprocess
import time
import signal
import sys
from pathlib import Path

# Configuration
# Assuming we run from project root, or script finds it
BINARY_PATH = Path("target/debug/wolf_prowler").resolve()
if not BINARY_PATH.exists():
    # Try alternate location if run from scripts/
    BINARY_PATH = Path("../target/debug/wolf_prowler").resolve()
NODES = 3
BASE_P2P_PORT = 10001
BASE_HTTP_PORT = 8081
TEST_DIR = Path("test_env").resolve()

def cleanup(signum, frame):
    print("\nStopping nodes...")
    # Pkill wolf_prowler in case
    subprocess.run(["pkill", "-f", "wolf_prowler"], stderr=subprocess.DEVNULL)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def main():
    if not BINARY_PATH.exists():
        print(f"Error: Binary not found at {BINARY_PATH}")
        sys.exit(1)
        
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    
    TEST_DIR.mkdir()

    processes = []
    
    print(f"Starting {NODES} nodes...")
    
    for i in range(NODES):
        node_id = i + 1
        node_dir = TEST_DIR / f"node{node_id}"
        node_dir.mkdir()
        
        # P2P Port
        p2p_port = BASE_P2P_PORT + i
        # HTTP Port
        http_port = BASE_HTTP_PORT + i
        
        env = os.environ.copy()
        env["WOLF_PROWLER_PORT"] = str(p2p_port)
        env["WOLF_PROWLER_DASHBOARD_PORT"] = str(http_port)
        env["WOLF_PROWLER_LOG_LEVEL"] = "info"
        
        # Ensure unique identity for each node
        key_path = node_dir / "identity.key"
        env["WOLF_KEYPAIR_PATH"] = str(key_path)
        
        # Run
        print(f"Launching Node {node_id}: P2P={p2p_port}, HTTP={http_port}")
        
        # We symlink the binary to avoid copying if possible, or just call it absolute
        # But we need CWD to be node_dir so identity.key is unique
        
        log_file = node_dir / "output.log"
        with open(log_file, "w") as f:
            p = subprocess.Popen(
                [str(BINARY_PATH)],
                cwd=node_dir,
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT
            )
            processes.append(p)
            
    print("\nNodes running. Access Dashboards at:")
    for i in range(NODES):
        print(f"Node {i+1}: http://localhost:{BASE_HTTP_PORT + i}/packs.html")
        
    print("\nPress Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
            # Check if any died
            for i, p in enumerate(processes):
                if p.poll() is not None:
                    print(f"Node {i+1} died! Check logs.")
    except KeyboardInterrupt:
        cleanup(None, None)

if __name__ == "__main__":
    main()
