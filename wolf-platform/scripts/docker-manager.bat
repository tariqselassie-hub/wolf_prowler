@echo off
setlocal enabledelayedexpansion

REM Wolf Prowler Docker Compose Management Script for Windows

title Wolf Prowler Docker Management

:main
if "%1"=="" goto help
if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="restart" goto restart
if "%1"=="status" goto status
if "%1"=="logs" goto logs
if "%1"=="monitoring" goto monitoring
if "%1"=="test" goto test
if "%1"=="cleanup" goto cleanup
goto help

:help
echo Wolf Prowler Docker Management Script
echo.
echo Usage: %0 {start^|stop^|restart^|status^|logs^|monitoring^|test^|cleanup}
echo.
echo Commands:
echo   start       - Build and start all services
echo   stop        - Stop all services
echo   restart     - Restart all services
echo   status      - Show service status
echo   logs [svc]  - Show logs (all or specific service)
echo   monitoring  - Start with monitoring stack
echo   test        - Test interoperability
echo   cleanup     - Remove all containers and data
echo.
echo Services:
echo   cap         - CAP node instance
echo   omega       - OMEGA node instance
echo   ccj         - CCJ node instance
echo.
echo Examples:
echo   %0 start                    # Start all services
echo   %0 logs cap                 # Show CAP logs
echo   %0 monitoring               # Start with monitoring
echo   %0 test                    # Test interoperability
goto end

:start
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Building and starting Wolf Prowler services...
echo.

REM Create directories
echo [INFO] Creating necessary directories...
if not exist "data" mkdir data
if not exist "data\cap" mkdir data\cap
if not exist "data\omega" mkdir data\omega
if not exist "data\ccj" mkdir data\ccj
if not exist "logs" mkdir logs
if not exist "logs\cap" mkdir logs\cap
if not exist "logs\omega" mkdir logs\omega
if not exist "logs\ccj" mkdir logs\ccj
if not exist "monitoring" mkdir monitoring
if not exist "monitoring\data" mkdir monitoring\data
if not exist "monitoring\grafana" mkdir monitoring\grafana

REM Build and start
docker-compose up --build -d

echo [INFO] Services are starting up...
echo [INFO] Waiting for services to be healthy...
timeout /t 20 /nobreak >nul

echo [INFO] Launching Wolf Control TUI...
start "Wolf Control" cmd /k "cargo run --bin wolf_control"

goto status

:stop
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Stopping Wolf Prowler services...
docker-compose down
echo [INFO] All services stopped.
goto end

:restart
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Restarting Wolf Prowler services...
docker-compose restart
echo [INFO] Services restarted.
goto end

:status
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Wolf Prowler Service Status:
echo.
docker-compose ps
echo.
echo [INFO] Service URLs:
echo CAP Dashboard:    https://localhost:3031
echo CAP API:          https://localhost:3031
echo OMEGA Dashboard:  http://localhost:3033
echo OMEGA API:        http://localhost:8082
echo CCJ Dashboard:    http://localhost:3035
echo CCJ API:          http://localhost:8083
echo.
goto end

:logs
if "%2"=="" (
    echo [INFO] Showing logs for all services...
    docker-compose logs -f
) else (
    echo [INFO] Showing logs for %2...
    docker-compose logs -f %2
)
goto end

:monitoring
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Starting Wolf Prowler with monitoring...

REM Create directories
if not exist "data" mkdir data
if not exist "data\cap" mkdir data\cap
if not exist "data\omega" mkdir data\omega
if not exist "data\ccj" mkdir data\ccj
if not exist "logs" mkdir logs
if not exist "logs\cap" mkdir logs\cap
if not exist "logs\omega" mkdir logs\omega
if not exist "logs\ccj" mkdir logs\ccj
if not exist "monitoring" mkdir monitoring
if not exist "monitoring\data" mkdir monitoring\data
if not exist "monitoring\grafana" mkdir monitoring\grafana

REM Start with monitoring profile
docker-compose --profile monitoring up --build -d

echo [INFO] Services with monitoring are starting up...
timeout /t 15 /nobreak >nul

goto status

:test
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [INFO] Testing interoperability between nodes...
echo.

echo [INFO] Testing CAP node...
curl -s http://localhost:3031/health >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] CAP node not responding
) else (
    echo [OK] CAP node responding
)

echo [INFO] Testing OMEGA node...
curl -s http://localhost:3033/health >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] OMEGA node not responding
) else (
    echo [OK] OMEGA node responding
)

echo [INFO] Testing CCJ node...
curl -s http://localhost:3035/health >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] CCJ node not responding
) else (
    echo [OK] CCJ node responding
)

echo.
echo [INFO] Testing peer connectivity...
curl -s http://localhost:8081/api/peers 2>nul || echo [WARN] Could not fetch peers from CAP
curl -s http://localhost:8082/api/peers 2>nul || echo [WARN] Could not fetch peers from OMEGA
curl -s http://localhost:8083/api/peers 2>nul || echo [WARN] Could not fetch peers from CCJ

echo.
echo [INFO] Interoperability test completed.
goto end

:cleanup
echo =====================================
echo  Wolf Prowler Docker Management
echo =====================================
echo [WARN] This will remove all containers, networks, and volumes.
set /p confirm="Are you sure? (y/N): "
if /i "!confirm!"=="y" (
    echo [INFO] Cleaning up Wolf Prowler environment...
    docker-compose down -v --remove-orphans
    docker system prune -f
    echo [INFO] Cleanup completed.
) else (
    echo [INFO] Cleanup cancelled.
)
goto end

:end
pause
