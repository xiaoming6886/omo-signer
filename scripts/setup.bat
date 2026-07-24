@echo off
echo ========================================
echo   OMO Signer - One-Click Setup
echo ========================================

cd /d "%~dp0.."

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ required
    pause & exit /b 1
)

echo [1/3] Installing dependencies...
pip install pynacl gmssl ecdsa -q

echo [2/3] Generating keys for all 7 agents...
for %%a in (sisyphus prometheus hephaestus atlas oracle metis momus) do (
    python src\omo_signer.py generate %%a >nul 2>&1
    python src\omo_signer.py generate %%a --sm2 >nul 2>&1
    python src\omo_signer.py generate %%a --ecdsa >nul 2>&1
)

echo [3/3] Starting daemon...
python src\omo_signing_daemon.py --daemon

echo.
echo ========================================
echo   Setup Complete!
echo   Test: python src\omo_signer.py sign oracle "hello"
echo   Status: python src\omo_signer.py ping
echo ========================================
pause
