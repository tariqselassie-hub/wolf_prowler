#!/bin/bash

# Wolf Prowler Docker Compose Management Script for Linux

# Function to display help
show_help() {
    echo "Wolf Prowler Docker Management Script"
    echo ""
    echo "Usage: $0 {start|stop|restart|status|logs|monitoring|test|cleanup}"
    echo ""
    echo "Commands:"
    echo "  start       - Build and start all services"
    echo "  stop        - Stop all services"
    echo "  prepare     - Prepare SQLx offline data (requires cargo sqlx)"
    echo "  restart     - Restart all services"
    echo "  status      - Show service status"
    echo "  logs [svc]  - Show logs (all or specific service)"
    echo "  shell [svc] - Open a shell in a service container"
    echo "  monitoring  - Start with monitoring stack"
    echo "  test        - Test interoperability"
    echo "  cleanup     - Remove all containers and data"
    echo ""
    echo "Services:"
    echo "  cap         - CAP node instance"
    echo "  omega       - OMEGA node instance"
    echo "  ccj         - CCJ node instance"
    echo ""
    echo "Examples:"
    echo "  $0 start                    # Start all services"
    echo "  $0 logs cap                 # Show CAP logs"
    echo "  $0 monitoring               # Start with monitoring"
    echo "  $0 test                     # Test interoperability"
}

# Detect Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

# Main logic
case "$1" in
    start)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Building and starting Wolf Prowler services..."
        echo ""

        # Clean up previous build artifacts to avoid confusion
        rm -f build.log build_error.txt

        # Create directories
        echo "[INFO] Creating necessary directories..."
        mkdir -p data/{cap,omega,ccj}
        mkdir -p logs/{cap,omega,ccj}
        mkdir -p monitoring/{data,grafana}

        # Start Database first
        echo "[INFO] Starting Database and Network..."
        $DOCKER_COMPOSE up -d postgres || echo "[WARN] 'postgres' service not found or failed to start separately."

        echo "[INFO] Waiting for Database initialization..."
        # Check for health status
        DB_ID=$($DOCKER_COMPOSE ps -q postgres 2>/dev/null)
        if [ -n "$DB_ID" ]; then
            echo -n "[INFO] Waiting for DB health..."
            for i in {1..30}; do
                HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{end}}' $DB_ID 2>/dev/null)
                if [ "$HEALTH" == "healthy" ]; then
                    echo " [OK]"
                    break
                fi
                if [ -z "$HEALTH" ]; then
                     echo " (No healthcheck detected) - Waiting 10s..."
                     sleep 10
                     break
                fi
                echo -n "."
                sleep 2
            done
            echo ""
        else
            sleep 10
        fi

        # Build and start remaining
        echo "[INFO] Building and starting all services..."
        # Use pipefail to catch build errors while streaming output
        set -o pipefail
        if ! $DOCKER_COMPOSE up --build -d 2>&1 | tee build.log; then
            echo "[ERROR] Build failed! Extracting errors to build_error.txt..."
            grep -C 5 "error" build.log > build_error.txt
            cat build_error.txt
            exit 1
        fi

        echo "[INFO] Services are starting up..."
        echo "[INFO] Waiting for services to be healthy..."
        sleep 20

        echo "[INFO] Launching Wolf Control TUI..."
        if command -v gnome-terminal &> /dev/null; then
            gnome-terminal --title="Wolf Control" -- bash -c "cargo run --bin wolf_control; exec bash"
        elif command -v xterm &> /dev/null; then
            xterm -T "Wolf Control" -e "cargo run --bin wolf_control; bash" &
        elif command -v konsole &> /dev/null; then
            konsole --new-tab -e "cargo run --bin wolf_control" &
        else
            echo "[WARN] No suitable terminal emulator found. Please run 'cargo run --bin wolf_control' manually."
        fi

        $0 status
        ;;

    prepare)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Preparing SQLx offline data..."

        # Ensure DB is accessible
        $DOCKER_COMPOSE up -d postgres
        echo "[INFO] Waiting for Database..."
        sleep 5

        echo "[INFO] Running cargo sqlx prepare..."
        # Connect to the local postgres container
        export DATABASE_URL="postgres://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler"
        # Run prepare for the workspace
        cargo sqlx prepare --workspace
        ;;

    stop)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Stopping Wolf Prowler services..."
        $DOCKER_COMPOSE down
        echo "[INFO] All services stopped."
        ;;

    restart)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Restarting Wolf Prowler services..."
        $DOCKER_COMPOSE restart
        echo "[INFO] Services restarted."
        ;;

    status)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Wolf Prowler Service Status:"
        echo ""
        $DOCKER_COMPOSE ps
        echo ""
        echo "[INFO] Service URLs:"
        echo "CAP Dashboard:    https://localhost:3031"
        echo "CAP API:          https://localhost:3031"
        echo "OMEGA Dashboard:  http://localhost:3033"
        echo "OMEGA API:        http://localhost:8082"
        echo "CCJ Dashboard:    http://localhost:3035"
        echo "CCJ API:          http://localhost:8083"
        echo ""
        ;;

    logs)
        if [ -z "$2" ]; then
            echo "[INFO] Showing logs for all services..."
            $DOCKER_COMPOSE logs -f
        else
            echo "[INFO] Showing logs for $2..."
            $DOCKER_COMPOSE logs -f $2
        fi
        ;;

    shell)
        if [ -z "$2" ]; then
            echo "[ERROR] Please specify a service (cap, omega, ccj, postgres)."
            exit 1
        fi
        echo "[INFO] Opening shell in $2..."
        $DOCKER_COMPOSE exec $2 /bin/bash || $DOCKER_COMPOSE exec $2 /bin/sh
        ;;

    monitoring)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Starting Wolf Prowler with monitoring..."

        # Create directories
        mkdir -p data/{cap,omega,ccj}
        mkdir -p logs/{cap,omega,ccj}
        mkdir -p monitoring/{data,grafana}

        # Start with monitoring profile
        $DOCKER_COMPOSE --profile monitoring up --build -d

        echo "[INFO] Services with monitoring are starting up..."
        sleep 15
        $0 status
        ;;

    test)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[INFO] Testing interoperability between nodes..."
        echo ""

        echo "[INFO] Testing CAP node..."
        if curl -s -k https://localhost:3031/health > /dev/null; then
            echo "[OK] CAP node responding"
        else
            echo "[ERROR] CAP node not responding"
        fi

        echo "[INFO] Testing OMEGA node..."
        if curl -s http://localhost:3033/health > /dev/null; then
            echo "[OK] OMEGA node responding"
        else
            echo "[ERROR] OMEGA node not responding"
        fi

        echo "[INFO] Testing CCJ node..."
        if curl -s http://localhost:3035/health > /dev/null; then
            echo "[OK] CCJ node responding"
        else
            echo "[ERROR] CCJ node not responding"
        fi

        echo ""
        echo "[INFO] Testing peer connectivity..."
        curl -s -k https://localhost:3031/api/peers > /dev/null || echo "[WARN] Could not fetch peers from CAP"
        curl -s http://localhost:8082/api/peers > /dev/null || echo "[WARN] Could not fetch peers from OMEGA"
        curl -s http://localhost:8083/api/peers > /dev/null || echo "[WARN] Could not fetch peers from CCJ"

        echo ""
        echo "[INFO] Interoperability test completed."
        ;;

    cleanup)
        echo "====================================="
        echo " Wolf Prowler Docker Management"
        echo "====================================="
        echo "[WARN] This will remove all containers, networks, and volumes."
        read -p "Are you sure? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            echo "[INFO] Cleaning up Wolf Prowler environment..."
            $DOCKER_COMPOSE down -v --remove-orphans
            echo "[INFO] Cleanup completed."
        else
            echo "[INFO] Cleanup cancelled."
        fi
        ;;

    *)
        show_help
        ;;
esac