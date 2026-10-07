#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EthKeepAlive - Mantém um adaptador Ethernet do Windows 11 ativo
================================================================

Gera trafego Ethernet/HTTP sintetico em um adaptador especifico
escolhido pelo usuario, impedindo que fique "ocioso". Inclui
servidor HTTP fake embutido para responder requisicoes locais,
watchdog para reconexao automatica e suporte a multiplos protocolos
(HTTP, ARP, DHCP, mixed).

Requer: Python 3.10+, Scapy, Npcap (modo compativel WinPcap).
Executar como Administrador.
"""

# ========================================================================
# 1. IMPORTS E CONSTANTES GLOBAIS
# ========================================================================
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

# Scapy e importado "preguicosamente" dentro das funcoes de trafego,
# para que --listar funcione mesmo sem Npcap/Scapy instalados.
try:
    from scapy.all import (
        ARP,
        BOOTP,
        DHCP,
        IP,
        TCP,
        UDP,
        Ether,
        Raw,
        conf,
        get_if_hwaddr,
        get_if_list,
        rdpcap,
        sendp,
    )
    SCAPY_OK = True
except Exception:  # pragma: no cover - ambiente sem scapy
    SCAPY_OK = False

APP_NAME = "EthKeepAlive"
APP_VERSION = "1.0.0"
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
DEFAULT_TARGET_IP = "192.168.1.1"
DEFAULT_PORT = 80
DEFAULT_INTERVAL = 2.0
WATCHDOG_INTERVAL = 5.0  # verifica status da interface a cada N segundos

# Estatisticas globais (atualizadas pelas threads)
STATS: dict[str, Any] = {
    "started_at": None,
    "pkts_sent": 0,
    "pkts_http": 0,
    "pkts_arp": 0,
    "pkts_dhcp": 0,
    "http_requests": 0,
    "reconnects": 0,
    "errors": 0,
}

STOP_EVENT = threading.Event()
LOGGER = logging.getLogger(APP_NAME)


# ========================================================================
# 2. FUNCOES UTILITARIAS
# ========================================================================
def timestamp() -> str:
    """Retorna timestamp curto para logs no formato [HH:MM:SS]."""
    return datetime.now().strftime("[%H:%M:%S]")


def iso_timestamp() -> str:
    """Retorna timestamp ISO 8601 com timezone UTC."""
    return datetime.now(timezone.utc).isoformat()


def log(msg: str, level: int = logging.INFO) -> None:
    """Imprime no logger e, quando permitido, no stdout."""
    LOGGER.log(level, msg)


def setup_logging(logfile: str | None, quiet: bool) -> None:
    """Configura logging em arquivo e/ou stdout."""
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.handlers.clear()

    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s",
                            datefmt="%H:%M:%S")

    if not quiet:
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)
        LOGGER.addHandler(sh)

    if logfile:
        try:
            fh = logging.FileHandler(logfile, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            LOGGER.addHandler(fh)
        except OSError as e:
            print(f"{timestamp()} Nao foi possivel abrir log '{logfile}': {e}",
                  file=sys.stderr)


def is_windows() -> bool:
    """Confere se estamos em Windows (recursos nativos exigem)."""
    return os.name == "nt" or sys.platform.startswith("win")


def is_admin() -> bool:
    """Verifica se o processo tem privilegios de administrador no Windows."""
    if not is_windows():
        return os.geteuid() == 0  # tolerado em Linux para teste
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ========================================================================
# 3. LISTAGEM DE DISPOSITIVOS (PowerShell / Get-NetAdapter)
# ========================================================================
def _run_powershell(script: str, timeout: float = 15.0) -> str:
    """Executa um bloco PowerShell e devolve stdout em texto."""
    if not is_windows():
        # Em ambiente nao-Windows, devolvemos vazio para que o chamador
        # exiba uma mensagem de erro.
        return ""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if completed.returncode != 0:
            LOGGER.debug("PowerShell falhou: %s", completed.stderr.strip())
        return completed.stdout
    except FileNotFoundError:
        LOGGER.error("PowerShell nao encontrado (precisa estar no PATH).")
        return ""
    except subprocess.TimeoutExpired:
        LOGGER.error("PowerShell demorou demais para responder.")
        return ""


def listar_dispositivos() -> list[dict]:
    """
    Lista TODOS os adaptadores do Windows via Get-NetAdapter.
    Retorna uma lista de dicionarios com campos padronizados.
    """
    script = (
        "Get-NetAdapter -IncludeHidden | "
        "Select-Object Name,InterfaceDescription,Status,MacAddress,"
        "LinkSpeed,ifIndex,DeviceID,MediaType | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    raw = _run_powershell(script)
    if not raw.strip():
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        LOGGER.error("Erro ao decodificar JSON do PowerShell: %s", e)
        return []

    # Se houver so um adaptador, PowerShell devolve objeto, nao lista
    if isinstance(data, dict):
        data = [data]

    adapters: list[dict] = []
    for i, item in enumerate(data, start=1):
        adapters.append({
            "id": i,
            "name": item.get("Name") or "",
            "description": item.get("InterfaceDescription") or "",
            "status": item.get("Status") or "",
            "mac": (item.get("MacAddress") or "").replace("-", ":").lower(),
            "linkspeed": item.get("LinkSpeed") or "",
            "ifindex": item.get("ifIndex") or 0,
            "device_id": item.get("DeviceID") or "",
            "media": item.get("MediaType") or "",
        })
    return adapters


def obter_power_management(name: str) -> dict | None:
    """
    Consulta Get-NetAdapterPowerManagement para o adaptador informado.
    Retorna None em caso de erro.
    """
    script = (
        f"try {{ Get-NetAdapterPowerManagement -Name '{name}' -ErrorAction Stop | "
        "Select-Object AllowComputerToTurnOffDevice,DeviceSleepOnDisconnect,"
        "SelectiveSuspend,WakeOnMagicPacket | "
        "ConvertTo-Json -Compress }} catch { '' }"
    )
    raw = _run_powershell(script)
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


# ========================================================================
# 4. EXIBICAO EM TABELA
# ========================================================================
def exibir_dispositivos(adapters: list[dict]) -> None:
    """Imprime os adaptadores em tabela formatada."""
    if not adapters:
        print("Nenhum adaptador encontrado. "
              "Execute como Administrador em Windows com PowerShell disponivel.")
        return

    header = ["ID", "Status", "Nome", "Descricao", "MAC", "LinkSpeed", "ifIndex"]
    widths = [3, 12, 18, 42, 19, 12, 7]

    def fmt_row(cols: list[str]) -> str:
        return "  ".join(c[:w].ljust(w) for c, w in zip(cols, widths))

    linha = "-" * (sum(widths) + 2 * (len(widths) - 1))
    print(linha)
    print(fmt_row(header))
    print(linha)
    for a in adapters:
        print(fmt_row([
            str(a["id"]),
            a["status"],
            a["name"],
            a["description"],
            a["mac"] or "-",
            a["linkspeed"] or "-",
            str(a["ifindex"]),
        ]))
    print(linha)


# ========================================================================
# 5. SELECAO DO DISPOSITIVO
# ========================================================================
def escolher_dispositivo(adapters: list[dict]) -> dict | None:
    """Modo interativo: pergunta ao usuario qual ID usar."""
    if not adapters:
        return None
    exibir_dispositivos(adapters)
    while True:
        try:
            escolha = input("\nDigite o ID do adaptador a manter ativo "
                            "(ou 'q' para sair): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if escolha.lower() in ("q", "quit", "sair"):
            return None
        if not escolha.isdigit():
            print("Entrada invalida. Informe um numero.")
            continue
        idx = int(escolha)
        for a in adapters:
            if a["id"] == idx:
                print(f"\n>> Selecionado: [{a['id']}] {a['description']} "
                      f"(iface='{a['name']}', mac={a['mac']})")
                return a
        print(f"ID {idx} nao encontrado.")


def localizar_por_id(adapters: list[dict], device_id: int) -> dict | None:
    for a in adapters:
        if a["id"] == device_id:
            return a
    return None


def localizar_por_nome(adapters: list[dict], nome: str) -> dict | None:
    nome_lc = nome.lower()
    for a in adapters:
        if a["name"].lower() == nome_lc:
            return a
    # fallback: match parcial pela descricao
    for a in adapters:
        if nome_lc in a["description"].lower():
            return a
    return None


# ========================================================================
# 6. RESOLUCAO DE INTERFACE SCAPY (nome Windows -> NPF device)
# ========================================================================
def resolver_scapy_iface(adapter: dict) -> str | None:
    """
    Scapy no Windows usa nomes do tipo '\\Device\\NPF_{GUID}'. Esta funcao
    tenta casar o adaptador escolhido com uma das interfaces conhecidas
    por Scapy, usando descricao ou MAC.
    """
    if not SCAPY_OK:
        return None
    desc = adapter["description"].lower()
    mac = adapter["mac"].lower()

    # Via conf.ifaces (API nova do Scapy no Windows)
    try:
        for name, iface in conf.ifaces.data.items():  # type: ignore[attr-defined]
            iface_desc = getattr(iface, "description", "") or ""
            iface_mac = (getattr(iface, "mac", "") or "").lower()
            if desc and iface_desc and desc == iface_desc.lower():
                return name
            if mac and iface_mac and mac == iface_mac:
                return name
    except Exception:
        pass

    # Fallback: get_if_list + match por hwaddr
    try:
        for iface in get_if_list():
            try:
                if mac and get_if_hwaddr(iface).lower() == mac:
                    return iface
            except Exception:
                continue
    except Exception:
        pass

    return None


# ========================================================================
# 7. CONSTRUCAO DE PACOTES
# ========================================================================
_HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "EthKeepAlive/1.0 (+keepalive)",
]
_HTTP_PATHS = ["/", "/index.html", "/api/ping", "/health", "/status", "/keepalive"]


def _build_http_payload(seq: int, method: str, host: str) -> bytes:
    """Monta um payload HTTP sintetico (GET ou POST)."""
    path = random.choice(_HTTP_PATHS)
    ua = random.choice(_HTTP_USER_AGENTS)
    ts = iso_timestamp()
    if method == "POST":
        body = json.dumps({"seq": seq, "ts": ts, "src": APP_NAME})
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: */*\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"X-Seq: {seq}\r\n"
            f"X-Ts: {ts}\r\n"
            f"\r\n"
            f"{body}"
        )
    else:
        req = (
            f"GET {path}?seq={seq} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: pt-BR,pt;q=0.9,en;q=0.8\r\n"
            f"Connection: keep-alive\r\n"
            f"X-Seq: {seq}\r\n"
            f"X-Ts: {ts}\r\n"
            f"\r\n"
        )
    return req.encode("utf-8", errors="replace")


def construir_pacote_http(seq: int, src_mac: str, dst_mac: str,
                          src_ip: str, dst_ip: str, dst_port: int) -> Any:
    """Monta um pacote Ether/IP/TCP com payload HTTP."""
    method = random.choice(["GET", "GET", "GET", "POST"])  # mais GETs
    sport = random.randint(49152, 65535)
    payload = _build_http_payload(seq, method, dst_ip)
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dst_port, flags="PA",
              seq=random.randint(1, 2**31 - 1))
        / Raw(load=payload)
    )
    return pkt


def construir_pacote_arp(src_mac: str, src_ip: str, dst_ip: str) -> Any:
    """ARP request (who-has dst_ip tell src_ip)."""
    return (
        Ether(src=src_mac, dst=MAC_BROADCAST)
        / ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00",
              pdst=dst_ip)
    )


def construir_pacote_dhcp(src_mac: str) -> Any:
    """DHCP Discover simulado (nao pede IP, so gera trafego L2/L3)."""
    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = bytes.fromhex(src_mac.replace(":", "")) + b"\x00" * 10
    return (
        Ether(src=src_mac, dst=MAC_BROADCAST)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


# ========================================================================
# 8. GERADOR DE TRAFEGO
# ========================================================================
def gerar_trafego(args: argparse.Namespace, adapter: dict,
                  scapy_iface: str) -> None:
    """
    Loop principal de envio. Alterna protocolos conforme --proto.
    Encerra ao receber STOP_EVENT.
    """
    try:
        src_mac = get_if_hwaddr(scapy_iface)
    except Exception:
        src_mac = adapter["mac"] or "02:00:00:00:00:01"
    src_ip = _guess_local_ip(adapter) or "0.0.0.0"
    dst_ip = args.target
    dst_mac = args.mac or MAC_BROADCAST
    dst_port = args.port
    interval = max(0.05, float(args.interval))

    log(f"Enviando trafego por iface Scapy='{scapy_iface}' "
        f"src_mac={src_mac} src_ip={src_ip} dst={dst_ip}:{dst_port} "
        f"dst_mac={dst_mac} proto={args.proto} intervalo={interval}s")

    seq = 0
    pcap_pkts: list[Any] | None = None
    if args.pcap:
        try:
            pcap_pkts = list(rdpcap(args.pcap))
            log(f"PCAP carregado: {args.pcap} ({len(pcap_pkts)} pacotes)")
        except Exception as e:
            log(f"Falha ao ler pcap '{args.pcap}': {e}", logging.ERROR)
            pcap_pkts = None

    proto_cycle = ["http", "arp", "dhcp"]

    while not STOP_EVENT.is_set():
        try:
            # Reproduz pcap se fornecido
            if pcap_pkts:
                for p in pcap_pkts:
                    if STOP_EVENT.is_set():
                        break
                    sendp(p, iface=scapy_iface, verbose=False)
                    STATS["pkts_sent"] += 1
                    time.sleep(interval)
                continue

            if args.proto == "mixed":
                proto = proto_cycle[seq % len(proto_cycle)]
            else:
                proto = args.proto

            if proto == "http":
                pkt = construir_pacote_http(seq, src_mac, dst_mac,
                                            src_ip, dst_ip, dst_port)
                STATS["pkts_http"] += 1
            elif proto == "arp":
                pkt = construir_pacote_arp(src_mac, src_ip, dst_ip)
                STATS["pkts_arp"] += 1
            elif proto == "dhcp":
                pkt = construir_pacote_dhcp(src_mac)
                STATS["pkts_dhcp"] += 1
            else:
                log(f"Protocolo desconhecido: {proto}", logging.WARNING)
                time.sleep(interval)
                continue

            sendp(pkt, iface=scapy_iface, verbose=False)
            STATS["pkts_sent"] += 1
            seq += 1

            if not args.quiet and (seq % 10 == 0 or seq <= 5):
                log(f"[{proto.upper()}] pacote #{seq} enviado "
                    f"(total={STATS['pkts_sent']})")

        except PermissionError as e:
            STATS["errors"] += 1
            log(f"Permissao negada ao enviar: {e}. "
                f"Execute como Administrador.", logging.ERROR)
            time.sleep(2.0)
        except OSError as e:
            STATS["errors"] += 1
            log(f"Erro de rede: {e}. Possivel interface fora do ar.",
                logging.WARNING)
            time.sleep(interval)
        except Exception as e:  # noqa: BLE001
            STATS["errors"] += 1
            log(f"Falha ao enviar pacote: {e}", logging.WARNING)

        STOP_EVENT.wait(interval)


def _guess_local_ip(adapter: dict) -> str | None:
    """Tenta descobrir um IPv4 do adaptador via PowerShell."""
    name = adapter["name"]
    if not name or not is_windows():
        return None
    script = (
        f"try {{ (Get-NetIPAddress -InterfaceAlias '{name}' "
        "-AddressFamily IPv4 -ErrorAction Stop | "
        "Select-Object -First 1).IPAddress }} catch { '' }"
    )
    out = _run_powershell(script).strip()
    return out or None


# ========================================================================
# 9. SERVIDOR HTTP FAKE (socket puro)
# ========================================================================
def servidor_http_fake(port: int) -> None:
    """
    HTTP server minimalista. Responde 200 OK com JSON a qualquer pedido.
    Roda em thread separada; encerra ao STOP_EVENT.
    """
    srv: socket.socket | None = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", port))
        srv.listen(16)
        log(f"HTTP fake escutando em 0.0.0.0:{port}")
    except OSError as e:
        log(f"Nao foi possivel abrir porta {port}: {e}", logging.ERROR)
        if srv:
            srv.close()
        return

    while not STOP_EVENT.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        t = threading.Thread(target=_atender_cliente_http,
                             args=(conn, addr), daemon=True)
        t.start()

    try:
        srv.close()
    except Exception:
        pass
    log("HTTP fake encerrado.")


def _atender_cliente_http(conn: socket.socket,
                          addr: tuple[str, int]) -> None:
    try:
        conn.settimeout(3.0)
        data = conn.recv(8192)
        req_line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        STATS["http_requests"] += 1
        log(f"HTTP {addr[0]}:{addr[1]} -> {req_line}")
        body = json.dumps({
            "status": "ok",
            "device": "emulado",
            "ts": iso_timestamp(),
            "app": APP_NAME,
        })
        resp = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {APP_NAME}/{APP_VERSION}\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        conn.sendall(resp.encode("utf-8"))
    except Exception as e:  # noqa: BLE001
        LOGGER.debug("Erro atendendo HTTP %s: %s", addr, e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ========================================================================
# 10. WATCHDOG DE INTERFACE
# ========================================================================
def watchdog_interface(adapter_name: str) -> None:
    """
    Verifica periodicamente se o adaptador continua Up.
    Loga quando cai e quando sobe novamente (nao reativa por si so;
    apenas sinaliza para o loop de trafego tentar continuar).
    """
    last_status: str | None = None
    while not STOP_EVENT.is_set():
        status = _status_adaptador(adapter_name)
        if status and status != last_status:
            if last_status is not None:
                if status == "Up":
                    STATS["reconnects"] += 1
                    log(f"Watchdog: '{adapter_name}' voltou ({status}).",
                        logging.INFO)
                else:
                    log(f"Watchdog: '{adapter_name}' mudou para {status}.",
                        logging.WARNING)
            last_status = status
        STOP_EVENT.wait(WATCHDOG_INTERVAL)


def _status_adaptador(name: str) -> str | None:
    script = (
        f"(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue)."
        "Status"
    )
    out = _run_powershell(script).strip()
    return out or None


def verificar_interface_ativa(adapter_name: str) -> bool:
    """Retorna True se o adaptador esta Up."""
    return (_status_adaptador(adapter_name) or "").lower() == "up"


# ========================================================================
# 11. CLI (argparse)
# ========================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ethkeepalive",
        description=(
            f"{APP_NAME} v{APP_VERSION} - Mantem um adaptador Ethernet do "
            "Windows ativo gerando trafego sintetico."
        ),
        epilog=(
            "Exemplos:\n"
            "  python ethkeepalive.py --listar\n"
            "  python ethkeepalive.py -d 2 -t 192.168.1.100 -n 1\n"
            "  python ethkeepalive.py -i \"Ethernet 2\" --proto mixed\n"
            "  python ethkeepalive.py            (modo interativo)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-l", "--listar", action="store_true",
                   help="Lista dispositivos e sai")
    p.add_argument("-d", "--device", type=int, default=None,
                   help="ID do dispositivo (ver --listar)")
    p.add_argument("-i", "--interface", type=str, default=None,
                   help="Nome ou descricao da interface (alternativa a -d)")
    p.add_argument("-t", "--target", type=str, default=DEFAULT_TARGET_IP,
                   help=f"IP de destino (padrao: {DEFAULT_TARGET_IP})")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                   help=f"Porta HTTP (padrao: {DEFAULT_PORT})")
    p.add_argument("-n", "--interval", type=float, default=DEFAULT_INTERVAL,
                   help=f"Intervalo entre pacotes em segundos "
                        f"(padrao: {DEFAULT_INTERVAL})")
    p.add_argument("-m", "--mac", type=str, default=None,
                   help="MAC de destino (padrao: broadcast)")
    p.add_argument("--proto", type=str, default="http",
                   choices=["http", "arp", "dhcp", "mixed"],
                   help="Protocolo do trafego (padrao: http)")
    p.add_argument("--sem-http", dest="sem_http", action="store_true",
                   help="Nao iniciar servidor HTTP fake")
    p.add_argument("--quiet", action="store_true",
                   help="Modo silencioso (apenas log em arquivo)")
    p.add_argument("--log", dest="logfile", type=str, default=None,
                   help="Arquivo de log (opcional)")
    p.add_argument("--pcap", type=str, default=None,
                   help="Reproduz pacotes de um arquivo .pcap em loop")
    p.add_argument("--check-power", action="store_true",
                   help="Mostra politicas de economia de energia dos "
                        "adaptadores e sai")
    p.add_argument("--version", action="version",
                   version=f"{APP_NAME} {APP_VERSION}")
    return p.parse_args(argv)


# ========================================================================
# 12. ORQUESTRACAO / MAIN
# ========================================================================
def _instalar_sinais() -> None:
    def _handler(signum, frame):  # noqa: ARG001
        if not STOP_EVENT.is_set():
            log("Sinal recebido, encerrando...", logging.INFO)
            STOP_EVENT.set()
    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except Exception:
        pass


def _resumo_estatisticas() -> None:
    started = STATS.get("started_at")
    dur = (time.time() - started) if started else 0.0
    print("\n" + "=" * 60)
    print(f"{APP_NAME} v{APP_VERSION} - resumo")
    print("=" * 60)
    print(f"Duracao:              {dur:,.1f} s")
    print(f"Pacotes enviados:     {STATS['pkts_sent']:,}")
    print(f"  - HTTP:             {STATS['pkts_http']:,}")
    print(f"  - ARP:              {STATS['pkts_arp']:,}")
    print(f"  - DHCP:             {STATS['pkts_dhcp']:,}")
    print(f"Requisicoes HTTP:     {STATS['http_requests']:,}")
    print(f"Reconexoes detectadas:{STATS['reconnects']:,}")
    print(f"Erros registrados:    {STATS['errors']:,}")
    print("=" * 60)


def _mostrar_power_management(adapters: list[dict]) -> None:
    print("Politicas de energia dos adaptadores (Get-NetAdapterPowerManagement):\n")
    for a in adapters:
        pm = obter_power_management(a["name"])
        if pm is None:
            print(f"  [{a['id']}] {a['name']}: (sem dados)")
            continue
        allow = pm.get("AllowComputerToTurnOffDevice", "?")
        sleep_disc = pm.get("DeviceSleepOnDisconnect", "?")
        selsusp = pm.get("SelectiveSuspend", "?")
        wake = pm.get("WakeOnMagicPacket", "?")
        aviso = ""
        if str(allow).lower() in ("enabled", "true", "1"):
            aviso = "  <-- ATENCAO: Windows pode desligar este dispositivo"
        print(f"  [{a['id']}] {a['name']}")
        print(f"       AllowComputerToTurnOffDevice = {allow}{aviso}")
        print(f"       DeviceSleepOnDisconnect      = {sleep_disc}")
        print(f"       SelectiveSuspend             = {selsusp}")
        print(f"       WakeOnMagicPacket            = {wake}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.logfile, args.quiet)
    _instalar_sinais()

    print(f"{APP_NAME} v{APP_VERSION}")
    if not is_windows():
        log("Aviso: este programa foi projetado para Windows 11. "
            "Em outros SOs, apenas o modo --listar e --check-power podem "
            "nao funcionar e o envio raw depende de permissoes equivalentes.",
            logging.WARNING)

    # Listagem simples
    adapters = listar_dispositivos()

    if args.listar:
        exibir_dispositivos(adapters)
        return 0

    if args.check_power:
        _mostrar_power_management(adapters)
        return 0

    if not adapters:
        log("Nenhum adaptador encontrado. Impossivel prosseguir.",
            logging.ERROR)
        return 2

    # Selecao
    adapter: dict | None = None
    if args.device is not None:
        adapter = localizar_por_id(adapters, args.device)
        if adapter is None:
            log(f"ID {args.device} nao encontrado. Use --listar.",
                logging.ERROR)
            return 2
    elif args.interface:
        adapter = localizar_por_nome(adapters, args.interface)
        if adapter is None:
            log(f"Interface '{args.interface}' nao encontrada. Use --listar.",
                logging.ERROR)
            return 2
    else:
        adapter = escolher_dispositivo(adapters)
        if adapter is None:
            log("Nenhum adaptador selecionado. Encerrando.", logging.INFO)
            return 0

    print(f"\n>> Mantendo ativo: '{adapter['description']}' "
          f"(iface='{adapter['name']}', status={adapter['status']}, "
          f"mac={adapter['mac']})\n")

    # Checagens para envio raw
    if not SCAPY_OK:
        log("Scapy nao esta disponivel. Rode: pip install scapy "
            "e instale Npcap em modo WinPcap-compatible.", logging.ERROR)
        return 3

    if is_windows() and not is_admin():
        log("AVISO: nao estou como Administrador. Envio raw de pacotes "
            "provavelmente vai falhar. Reexecute em um prompt elevado.",
            logging.WARNING)

    scapy_iface = resolver_scapy_iface(adapter)
    if not scapy_iface:
        log("Nao consegui mapear o adaptador para uma interface do Scapy. "
            "Verifique se o Npcap esta instalado em modo "
            "WinPcap-compatible.", logging.ERROR)
        return 4
    log(f"Interface Scapy resolvida: {scapy_iface}")

    STATS["started_at"] = time.time()

    threads: list[threading.Thread] = []

    # Servidor HTTP
    if not args.sem_http:
        t_http = threading.Thread(target=servidor_http_fake,
                                  args=(args.port,), daemon=True,
                                  name="http-fake")
        t_http.start()
        threads.append(t_http)
    else:
        log("Servidor HTTP fake desativado (--sem-http).")

    # Watchdog
    t_wd = threading.Thread(target=watchdog_interface,
                            args=(adapter["name"],),
                            daemon=True, name="watchdog")
    t_wd.start()
    threads.append(t_wd)

    # Trafego
    t_tx = threading.Thread(target=gerar_trafego,
                            args=(args, adapter, scapy_iface),
                            daemon=True, name="tx")
    t_tx.start()
    threads.append(t_tx)

    try:
        while not STOP_EVENT.is_set():
            STOP_EVENT.wait(1.0)
            if not t_tx.is_alive():
                log("Thread de trafego terminou inesperadamente. Encerrando.",
                    logging.ERROR)
                STOP_EVENT.set()
                break
    except KeyboardInterrupt:
        STOP_EVENT.set()
    finally:
        STOP_EVENT.set()
        for t in threads:
            t.join(timeout=3.0)
        _resumo_estatisticas()
    return 0


if __name__ == "__main__":
    sys.exit(main())
