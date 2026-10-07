@echo off
REM ============================================================
REM  EthKeepAlive - launcher Windows
REM  Executa o projeto em um console, com auto-elevacao UAC
REM  e verificacao de dependencias (Python + Scapy).
REM
REM  Uso:
REM    ethkeepalive.bat                      -> --anti-idle --lock-nic (padrao)
REM    ethkeepalive.bat --listar             -> repassa qualquer argumento
REM    ethkeepalive.bat -d 2 --proto mixed   -> idem
REM ============================================================

setlocal EnableExtensions EnableDelayedExpansion
title EthKeepAlive
cd /d "%~dp0"

REM ---------- Verifica privilegio de Administrador ----------
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo ============================================================
    echo  EthKeepAlive precisa ser executado como ADMINISTRADOR.
    echo  Vou tentar reabrir com elevacao via UAC...
    echo ============================================================
    echo.
    REM Reabre este mesmo .bat elevado, mantendo os argumentos
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b 0
)

REM ---------- Verifica Python ----------
where python >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo [ERRO] Python nao encontrado no PATH.
    echo        Instale em https://www.python.org/downloads/windows/
    echo        marcando "Add Python to PATH".
    echo.
    pause
    exit /b 2
)

REM ---------- Verifica Scapy ----------
python -c "import scapy" >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [INFO] Dependencia 'scapy' nao encontrada. Instalando...
    python -m pip install --quiet --disable-pip-version-check scapy
    if %errorLevel% NEQ 0 (
        echo [ERRO] Falha ao instalar scapy. Rode manualmente:
        echo        pip install scapy
        pause
        exit /b 3
    )
)

REM ---------- Lembrete sobre Npcap ----------
if not exist "C:\Windows\System32\Npcap" if not exist "C:\Windows\SysWOW64\Npcap" (
    echo.
    echo [AVISO] Npcap parece nao estar instalado.
    echo         O envio raw de pacotes falhara sem ele.
    echo         Baixe em: https://npcap.com/#download
    echo         Marque "Install Npcap in WinPcap API-compatible Mode".
    echo.
    choice /c SN /n /m "Continuar mesmo assim? [S/N] "
    if errorlevel 2 exit /b 4
)

REM ---------- Execucao ----------
echo.
echo ============================================================
echo  EthKeepAlive iniciando (Ctrl+C para encerrar)
echo ============================================================
echo.

if "%~1"=="" (
    REM Defaults recomendados: adaptativo + lock-nic + raw-only + fast
    REM --fast  = interval 0.5s, jitter 0.15, burst 3, modo aggressive
    REM --raw-only = so Scapy sendp, nao depende de IPv4 na NIC
    python ethkeepalive.py --anti-idle --lock-nic --raw-only --fast
) else (
    python ethkeepalive.py %*
)
set EXITCODE=%errorLevel%

echo.
echo ============================================================
echo  EthKeepAlive encerrado (exit=%EXITCODE%).
echo  Pressione qualquer tecla para fechar esta janela.
echo ============================================================
pause >nul
exit /b %EXITCODE%
