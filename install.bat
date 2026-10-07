@echo off
REM ============================================================
REM  EthKeepAlive - instalador automatizado (Windows x64)
REM
REM  Baixa para a subpasta .\deps\ :
REM    - Python 3.12 (instalador para all users)
REM    - Npcap (instalador oficial)
REM  Instala Python de modo silencioso.
REM  Executa 'pip install scapy'.
REM  Abre o instalador do Npcap para o usuario marcar
REM  "Install Npcap in WinPcap API-compatible Mode".
REM
REM  Uso: botao direito -> Executar como administrador
REM ============================================================

setlocal EnableExtensions EnableDelayedExpansion
title EthKeepAlive - Instalador
cd /d "%~dp0"

REM ---------- Admin ----------
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo ============================================================
    echo  Este instalador precisa ser executado como ADMINISTRADOR.
    echo  Vou reabrir com elevacao via UAC...
    echo ============================================================
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

if not exist "deps" mkdir "deps"

echo.
echo ============================================================
echo  EthKeepAlive - Instalador
echo ============================================================
echo.

REM =========================================================
REM  1) Python
REM =========================================================
set "PY_URL=https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe"
set "PY_EXE=%cd%\deps\python-3.12.5-amd64.exe"

where python >nul 2>&1
if %errorLevel% EQU 0 (
    echo [1/4] Python ja esta no PATH. Pulando download.
    goto :pip_scapy
)

echo [1/4] Baixando Python 3.12.5...
echo        %PY_URL%
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_EXE%' -UseBasicParsing } catch { Write-Host $_.Exception.Message; exit 1 }"
if %errorLevel% NEQ 0 (
    echo [ERRO] Falha ao baixar Python.
    echo        Baixe manualmente em https://www.python.org/downloads/windows/
    pause
    exit /b 2
)

echo [1/4] Instalando Python (silencioso, PATH para todos os usuarios)...
"%PY_EXE%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_launcher=1 ^
    SimpleInstall=1 Shortcuts=0
if %errorLevel% NEQ 0 (
    echo [ERRO] Instalador do Python retornou %errorLevel%.
    echo        Execute '%PY_EXE%' manualmente.
    pause
    exit /b 3
)

REM Atualiza PATH da sessao atual
set "PATH=%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts;%PATH%"

:pip_scapy
REM =========================================================
REM  2) Scapy
REM =========================================================
echo.
echo [2/4] Instalando dependencia Python: scapy
python -m pip install --upgrade --disable-pip-version-check pip >nul
python -m pip install --disable-pip-version-check scapy
if %errorLevel% NEQ 0 (
    echo [ERRO] Falha em 'pip install scapy'.
    pause
    exit /b 4
)

REM =========================================================
REM  3) Npcap - download e abertura do instalador
REM =========================================================
set "NPCAP_URL=https://npcap.com/dist/npcap-1.80.exe"
set "NPCAP_EXE=%cd%\deps\npcap-1.80.exe"

echo.
echo [3/4] Verificando Npcap...
if exist "%SystemRoot%\System32\Npcap\" (
    echo       Npcap ja instalado em %SystemRoot%\System32\Npcap. Pulando.
    goto :pos_npcap
)

echo [3/4] Baixando Npcap...
echo        %NPCAP_URL%
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_EXE%' -UseBasicParsing } catch { Write-Host $_.Exception.Message; exit 1 }"
if %errorLevel% NEQ 0 (
    echo [AVISO] Falha ao baixar Npcap. Baixe manualmente:
    echo         https://npcap.com/#download
    echo         e salve em: %cd%\deps\
    pause
    goto :pos_npcap
)

echo.
echo ============================================================
echo  Abrindo instalador do Npcap. MARQUE:
echo    [X] Install Npcap in WinPcap API-compatible Mode
echo  As demais opcoes podem ficar nos valores padrao.
echo  Clique em "I Agree" e finalize antes de continuar.
echo ============================================================
echo.
pause
start /wait "" "%NPCAP_EXE%"

:pos_npcap
REM =========================================================
REM  4) Teste final
REM =========================================================
echo.
echo [4/4] Verificando instalacao...
python -c "import scapy; print('scapy', scapy.__version__)" 2>nul
if %errorLevel% NEQ 0 (
    echo [AVISO] Scapy nao foi importado corretamente.
) else (
    echo       scapy OK.
)

python ethkeepalive.py --listar >nul 2>&1
if %errorLevel% EQU 0 (
    echo       ethkeepalive.py --listar: OK
) else (
    echo [AVISO] 'ethkeepalive.py --listar' retornou erro.
    echo         Verifique se o Npcap esta em modo WinPcap-compatible.
)

echo.
echo ============================================================
echo  Instalacao concluida.
echo  Agora voce pode rodar:
echo    ethkeepalive.bat             (anti-idle + lock-nic)
echo    ethkeepalive-listar.bat      (lista adaptadores)
echo    python ethkeepalive.py --help
echo ============================================================
echo.
pause
exit /b 0
