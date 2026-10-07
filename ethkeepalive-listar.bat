@echo off
REM ============================================================
REM  Atalho: lista os adaptadores do Windows e espera input.
REM  Nao exige Administrador (so leitura via Get-NetAdapter).
REM ============================================================
setlocal
title EthKeepAlive - listar adaptadores
cd /d "%~dp0"

where python >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERRO] Python nao encontrado no PATH.
    pause
    exit /b 2
)

python ethkeepalive.py --listar
echo.
pause
