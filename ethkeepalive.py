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

# Limites de seguranca - protegem o usuario contra configuracoes abusivas.
SAFETY_MIN_INTERVAL = 0.5   # nunca enviar mais rapido que isto (segundos)
SAFETY_MAX_INTERVAL = 300.0
SAFETY_MAX_PAYLOAD = 2048   # bytes por requisicao
SAFETY_MAX_CONCURRENT = 1   # conexoes TCP simultaneas no modo adaptativo

# Ciclos do keep-alive adaptativo (sequencia A..F da especificacao)
CICLOS_ADAPTATIVO = ["icmp", "tcp", "http_get", "http_head", "http_post", "arp"]

# Estatisticas globais (atualizadas pelas threads)
STATS: dict[str, Any] = {
    "started_at": None,
    "pkts_sent": 0,
    "pkts_http": 0,
    "pkts_arp": 0,
    "pkts_dhcp": 0,
    "icmp_sent": 0,
    "arp_sent": 0,
    "http_sent": 0,
    "tcp_connected": 0,
    "bytes_sent": 0,
    "http_requests": 0,
    "reconnects": 0,
    "errors": 0,
    # Testes de conectividade real (adaptativo)
    "ok_icmp": 0, "fail_icmp": 0,
    "ok_tcp": 0, "fail_tcp": 0,
    "ok_http": 0, "fail_http": 0,
    "ok_arp": 0, "fail_arp": 0,
    "state_changes": 0,
}


class EstadoKA:
    """Estados da maquina de estados do AdaptiveKeepAlive."""
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    RECOVERING = "RECOVERING"


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
# 10.5. ADAPTIVE KEEP-ALIVE (camada principal de resiliencia)
# ========================================================================
def _probe_tcp(src_ip: str | None, target_ip: str, target_port: int,
               timeout: float = 2.0) -> tuple[bool, float]:
    """Tenta um TCP connect pequeno a partir de src_ip. Retorna (ok, ms)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if src_ip:
            try:
                s.bind((src_ip, 0))
            except OSError as e:
                LOGGER.debug("bind(%s,0) falhou: %s", src_ip, e)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((target_ip, target_port))
        return True, (time.time() - t0) * 1000
    except Exception as e:
        LOGGER.debug("probe_tcp %s:%s falhou: %s", target_ip, target_port, e)
        return False, 0.0
    finally:
        try:
            s.close()
        except Exception:
            pass


def imprimir_cabecalho_interface(adapter: dict, scapy_iface: str,
                                 src_ip: str | None, src_mac: str,
                                 src_ipv6: str | None = None) -> None:
    """Exibe o resumo da interface selecionada e informa sobre o binding."""
    print("\nInterface selecionada:")
    print(f"  Nome:        {adapter['name']}")
    print(f"  Descricao:   {adapter['description']}")
    print(f"  ifIndex:     {adapter['ifindex']}")
    print(f"  IPv4:        {src_ip or '(nao detectado)'}")
    print(f"  IPv6:        {src_ipv6 or '(nao detectado)'}")
    print(f"  MAC:         {adapter['mac'] or '(desconhecido)'}")
    print(f"  LinkSpeed:   {adapter['linkspeed']}")
    print(f"  Scapy iface: {scapy_iface}")
    if src_ip:
        print("O trafego sera associado a esta interface (bind no IPv4 "
              "+ envio raw pela Scapy iface).")
    else:
        print("ATENCAO: nao foi possivel detectar IPv4 do adaptador. "
              "Sockets TCP/HTTP podem usar outra NIC. Envio raw continua "
              "preso a interface Scapy escolhida.")


def _guess_local_ipv6(adapter: dict) -> str | None:
    """Tenta descobrir um endereco IPv6 global do adaptador."""
    name = adapter["name"]
    if not name or not is_windows():
        return None
    script = (
        f"try {{ (Get-NetIPAddress -InterfaceAlias '{name}' "
        "-AddressFamily IPv6 -ErrorAction Stop | "
        "Where-Object { $_.IPAddress -notlike 'fe80*' } | "
        "Select-Object -First 1).IPAddress }} catch { '' }"
    )
    out = _run_powershell(script).strip()
    return out or None


def _ler_bytes_interface(adapter_name: str) -> tuple[int, int] | None:
    """Retorna (bytes_rx, bytes_tx) do adaptador via Get-NetAdapterStatistics."""
    script = (
        f"try {{ Get-NetAdapterStatistics -Name '{adapter_name}' "
        "-ErrorAction Stop | "
        "Select-Object ReceivedBytes,SentBytes | ConvertTo-Json -Compress "
        "}} catch { '' }"
    )
    raw = _run_powershell(script).strip()
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return int(d.get("ReceivedBytes", 0)), int(d.get("SentBytes", 0))
    except (json.JSONDecodeError, ValueError):
        return None


class AdaptiveKeepAlive:
    """
    Camada adaptativa que alterna entre varios testes de conectividade real
    (ICMP, TCP connect, HTTP GET/HEAD/POST, ARP) em uma unica NIC. Mantem
    uma maquina de estados (STARTING / HEALTHY / DEGRADED / DISCONNECTED /
    RECOVERING) e aplica backoff/jitter dentro de limites de seguranca.
    """

    def __init__(self, args: argparse.Namespace, adapter: dict,
                 scapy_iface: str, src_ip: str | None, src_mac: str) -> None:
        self.args = args
        self.adapter = adapter
        self.scapy_iface = scapy_iface
        self.src_ip = src_ip or None
        self.src_mac = src_mac
        self.target_ip = args.target
        self.target_port = args.target_port or args.port or 80
        self.http_host = args.http_host or args.target
        self.http_url = args.http_url or "/"
        self.mode = args.keepalive_mode  # basic|adaptive|aggressive
        self.tcp_mode = args.tcp_mode    # short|keep-alive

        # Intervalos (sempre dentro de limites seguros)
        self.min_interval = max(SAFETY_MIN_INTERVAL,
                                float(args.min_interval))
        self.max_interval = max(self.min_interval,
                                min(SAFETY_MAX_INTERVAL,
                                    float(args.max_interval)))
        self.base_interval = max(self.min_interval,
                                 min(self.max_interval, float(args.interval)))
        self.jitter = max(0.0, min(float(args.jitter), 5.0))
        self.current_interval = self.base_interval

        # Estado
        self.state = EstadoKA.STARTING
        self.last_activity = time.time()
        self.last_success = time.time()
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.cycle_index = 0
        self._interface_up = True
        self._conn_lock = threading.Lock()  # garante no maximo 1 conexao
        self._keep_sock: socket.socket | None = None

    # ----- Estado -----
    def set_state(self, novo: str) -> None:
        if novo != self.state:
            log(f"STATE: {self.state} -> {novo}")
            self.state = novo
            STATS["state_changes"] += 1

    def set_interface_status(self, up: bool) -> None:
        """Chamado pelo watchdog quando o status muda."""
        was_up = self._interface_up
        self._interface_up = up
        if was_up and not up:
            self._close_keep_sock()
            self.set_state(EstadoKA.DISCONNECTED)
        elif not was_up and up:
            self.set_state(EstadoKA.RECOVERING)

    # ----- Testes -----
    def _close_keep_sock(self) -> None:
        if self._keep_sock is not None:
            try:
                self._keep_sock.close()
            except Exception:
                pass
            self._keep_sock = None

    def _next_test(self) -> str:
        if self.mode == "basic":
            return "http_get"
        kind = CICLOS_ADAPTATIVO[self.cycle_index % len(CICLOS_ADAPTATIVO)]
        self.cycle_index += 1
        return kind

    def _record_success(self, kind: str) -> None:
        STATS[f"ok_{kind}"] = STATS.get(f"ok_{kind}", 0) + 1
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        self.last_activity = time.time()
        self.last_success = time.time()
        if self.current_interval > self.base_interval:
            self.current_interval = max(self.base_interval,
                                        self.current_interval * 0.8)
        if self.state in (EstadoKA.RECOVERING, EstadoKA.STARTING,
                          EstadoKA.DEGRADED):
            if self.consecutive_successes >= 2:
                self.set_state(EstadoKA.HEALTHY)

    def _record_failure(self, kind: str) -> None:
        STATS[f"fail_{kind}"] = STATS.get(f"fail_{kind}", 0) + 1
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.last_activity = time.time()
        if self.consecutive_failures >= 3:
            # backoff exponencial controlado
            self.current_interval = min(self.max_interval,
                                        self.current_interval * 1.5)
            if self.state == EstadoKA.HEALTHY:
                self.set_state(EstadoKA.DEGRADED)

    def _test_icmp(self) -> bool:
        """ICMP echo request via Scapy, com src_ip e iface forcados."""
        try:
            from scapy.all import sr1, ICMP  # import local - precisa Npcap
            seq = STATS["icmp_sent"] & 0xFFFF
            pkt = IP(src=self.src_ip or "0.0.0.0", dst=self.target_ip) / \
                ICMP(id=seq, seq=seq) / Raw(load=b"EKA")
            STATS["icmp_sent"] += 1
            STATS["pkts_sent"] += 1
            reply = sr1(pkt, iface=self.scapy_iface, timeout=1,
                        verbose=False)
            if reply is not None:
                log(f"[ICMP] ok -> {self.target_ip}")
                self._record_success("icmp")
                return True
            log(f"[ICMP] sem resposta -> {self.target_ip}",
                logging.WARNING)
            self._record_failure("icmp")
            return False
        except PermissionError:
            log("[ICMP] PermissionError (precisa Administrador).",
                logging.ERROR)
            self._record_failure("icmp")
            return False
        except Exception as e:  # noqa: BLE001
            log(f"[ICMP] erro: {e}", logging.WARNING)
            self._record_failure("icmp")
            return False

    def _test_tcp(self) -> bool:
        """TCP connect curto, bind ao IPv4 do adaptador."""
        with self._conn_lock:
            ok, dt = _probe_tcp(self.src_ip, self.target_ip,
                                self.target_port, timeout=2.0)
            if ok:
                STATS["tcp_connected"] += 1
                log(f"[TCP] connect {self.target_ip}:{self.target_port} "
                    f"({dt:.0f}ms)")
                self._record_success("tcp")
            else:
                log(f"[TCP] falhou -> "
                    f"{self.target_ip}:{self.target_port}",
                    logging.WARNING)
                self._record_failure("tcp")
            return ok

    def _http_request(self, method: str) -> bool:
        """Realiza HTTP curto, bind no IPv4 do adaptador."""
        with self._conn_lock:
            keep_alive = (self.tcp_mode == "keep-alive")
            s: socket.socket | None
            reused = False
            if keep_alive and self._keep_sock is not None:
                s = self._keep_sock
                reused = True
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    if self.src_ip:
                        s.bind((self.src_ip, 0))
                except OSError as e:
                    LOGGER.debug("http bind %s falhou: %s", self.src_ip, e)
                s.settimeout(3.0)
                try:
                    s.connect((self.target_ip, self.target_port))
                except Exception as e:  # noqa: BLE001
                    log(f"[HTTP {method}] connect falhou: {e}",
                        logging.WARNING)
                    self._record_failure("http")
                    try:
                        s.close()
                    except Exception:
                        pass
                    return False

            try:
                seq = STATS["http_sent"] + 1
                body = ""
                if method == "POST":
                    body = json.dumps({
                        "client": APP_NAME,
                        "sequence": seq,
                        "timestamp": iso_timestamp(),
                    })
                conn_hdr = "keep-alive" if keep_alive else "close"
                headers = [
                    f"{method} {self.http_url} HTTP/1.1",
                    f"Host: {self.http_host}",
                    f"User-Agent: {APP_NAME}/{APP_VERSION}",
                    "Accept: */*",
                    f"Connection: {conn_hdr}",
                ]
                if method == "POST":
                    headers += [
                        "Content-Type: application/json",
                        f"Content-Length: {len(body)}",
                    ]
                req = ("\r\n".join(headers) + "\r\n\r\n" + body)
                data = req.encode("utf-8", errors="replace")
                if len(data) > SAFETY_MAX_PAYLOAD:
                    data = data[:SAFETY_MAX_PAYLOAD]
                s.sendall(data)
                STATS["http_sent"] = seq
                STATS["pkts_sent"] += 1
                STATS["pkts_http"] += 1
                STATS["bytes_sent"] += len(data)

                resp = s.recv(4096)
                if resp.startswith(b"HTTP/"):
                    status_line = resp.split(b"\r\n", 1)[0].decode(
                        "latin-1", "ignore")
                    log(f"[HTTP {method}] {status_line}"
                        + (" (reused)" if reused else ""))
                    self._record_success("http")
                    ok = True
                else:
                    log(f"[HTTP {method}] resposta nao-HTTP "
                        f"({len(resp)} bytes)", logging.WARNING)
                    self._record_failure("http")
                    ok = False
            except Exception as e:  # noqa: BLE001
                log(f"[HTTP {method}] erro: {e}", logging.WARNING)
                self._record_failure("http")
                ok = False

            # Nunca deixa socket morto. No modo keep-alive, so reaproveita
            # se a transacao foi bem sucedida.
            if keep_alive and ok:
                self._keep_sock = s
            else:
                try:
                    s.close()
                except Exception:
                    pass
                if self._keep_sock is s:
                    self._keep_sock = None
            return ok

    def _test_arp(self) -> bool:
        try:
            from scapy.all import srp1
            pkt = (
                Ether(src=self.src_mac, dst=MAC_BROADCAST)
                / ARP(op=1, hwsrc=self.src_mac,
                      psrc=self.src_ip or "0.0.0.0",
                      hwdst="00:00:00:00:00:00",
                      pdst=self.target_ip)
            )
            STATS["arp_sent"] += 1
            STATS["pkts_arp"] += 1
            STATS["pkts_sent"] += 1
            reply = srp1(pkt, iface=self.scapy_iface, timeout=1,
                         verbose=False)
            if reply is not None:
                log(f"[ARP] reply recebido de {self.target_ip}")
                self._record_success("arp")
                return True
            # Alvo fora da LAN provavelmente nao responde ARP:
            # isso nao conta como falha critica.
            log(f"[ARP] sem reply (alvo pode nao estar na LAN)")
            self._record_success("arp")  # considera sucesso de envio
            return True
        except Exception as e:  # noqa: BLE001
            log(f"[ARP] erro: {e}", logging.WARNING)
            self._record_failure("arp")
            return False

    # ----- Loop principal -----
    def _log_status(self) -> None:
        now = time.time()
        act = now - self.last_activity
        suc = now - self.last_success
        log(f"[KEEPALIVE] Estado: {self.state} | "
            f"Ultima atividade: {act:.1f}s | "
            f"Ultimo sucesso: {suc:.1f}s | "
            f"intervalo: {self.current_interval:.2f}s")

    def _sleep_jitter(self) -> None:
        base = self.current_interval
        if self.jitter > 0:
            delta = random.uniform(-self.jitter, self.jitter)
            wait = base + delta
        else:
            wait = base
        wait = max(self.min_interval, min(self.max_interval, wait))
        STOP_EVENT.wait(wait)

    def run(self) -> None:
        """Loop principal do keep-alive adaptativo."""
        log(f"AdaptiveKeepAlive iniciado (modo={self.mode}, "
            f"base={self.base_interval:.2f}s, jitter={self.jitter}s, "
            f"min={self.min_interval}s, max={self.max_interval}s, "
            f"tcp={self.tcp_mode})")
        self.set_state(EstadoKA.STARTING)

        # Backoff state para 'target nao responde'
        aggressive_silence = 20.0  # modo aggressive: 20s sem sucesso -> acelera
        last_status_log = 0.0
        did_initial = False

        while not STOP_EVENT.is_set():
            if not self._interface_up:
                # watchdog ja sinalizou; aguarda a volta
                STOP_EVENT.wait(1.0)
                continue

            if not did_initial:
                self.set_state(EstadoKA.HEALTHY)
                did_initial = True

            if self.state == EstadoKA.RECOVERING:
                log("[WATCHDOG] Reiniciando keep-alive")
                self.consecutive_failures = 0
                self.current_interval = self.base_interval

            kind = self._next_test()
            try:
                if kind == "icmp":
                    self._test_icmp()
                elif kind == "tcp":
                    self._test_tcp()
                elif kind == "http_get":
                    self._http_request("GET")
                elif kind == "http_head":
                    self._http_request("HEAD")
                elif kind == "http_post":
                    self._http_request("POST")
                elif kind == "arp":
                    self._test_arp()
            except Exception as e:  # noqa: BLE001
                STATS["errors"] += 1
                log(f"Erro inesperado no ciclo {kind}: {e}", logging.ERROR)

            # Modo aggressive: encurta temporariamente quando ha silencio util
            if self.mode == "aggressive":
                silencio = time.time() - self.last_success
                if silencio > aggressive_silence:
                    novo = max(self.min_interval, self.base_interval * 0.5)
                    if abs(novo - self.current_interval) > 0.1:
                        self.current_interval = novo
                        log(f"[KEEPALIVE] WARNING: {silencio:.1f}s sem "
                            f"sucesso. Reduzindo intervalo para "
                            f"{self.current_interval:.2f}s.",
                            logging.WARNING)

            # Log periodico de estado
            now = time.time()
            if now - last_status_log >= 15.0:
                self._log_status()
                last_status_log = now

            self._sleep_jitter()

        self._close_keep_sock()
        log("AdaptiveKeepAlive encerrado.")


def watchdog_interface_adaptive(adapter_name: str,
                                aka: AdaptiveKeepAlive) -> None:
    """
    Watchdog da interface vinculado a um AdaptiveKeepAlive. Monitora
    Get-NetAdapter periodicamente e sinaliza mudancas de estado.
    """
    last_status: str | None = None
    while not STOP_EVENT.is_set():
        status = (_status_adaptador(adapter_name) or "").strip()
        if status != (last_status or ""):
            if last_status is None:
                last_status = status
            else:
                low = status.lower()
                if low == "up":
                    STATS["reconnects"] += 1
                    log(f"[WATCHDOG] Interface voltou ({status}).")
                    aka.set_interface_status(True)
                elif low in ("down", "disconnected"):
                    log(f"[WATCHDOG] Interface caiu ({status}).",
                        logging.WARNING)
                    aka.set_interface_status(False)
                elif low == "disabled":
                    log("[WATCHDOG] Interface administrativamente "
                        "desabilitada.", logging.WARNING)
                    aka.set_interface_status(False)
                else:
                    log(f"[WATCHDOG] Status desconhecido: '{status}'.",
                        logging.WARNING)
                last_status = status
        STOP_EVENT.wait(WATCHDOG_INTERVAL)


# ========================================================================
# 10.55. NIC LOCK - tenta impedir que o Windows desative/bloqueie a NIC
# ========================================================================
# IMPORTANTE: isto exige Administrador e NAO substitui politicas de grupo
# (GPO) nem drivers que ignorem Set-NetAdapterPowerManagement. O programa
# salva o estado original no boot e RESTAURA ao encerrar (SIGINT/SIGTERM
# ou excecao do main). Uma thread guardia reaplica o lock se algo externo
# tentar desfazer durante a execucao.

# Guarda do estado original para restauracao
_NIC_SNAPSHOT: dict[str, Any] = {}
_NIC_LOCK_LOCK = threading.Lock()


def _ps_bool_arg(v: Any) -> str:
    """Converte um valor PowerShell em 'Enabled'/'Disabled' para o cmdlet."""
    s = str(v).strip().lower()
    if s in ("enabled", "true", "1"):
        return "Enabled"
    if s in ("disabled", "false", "0"):
        return "Disabled"
    return "Disabled"


def bloquear_nic(adapter_name: str) -> dict:
    """
    Tenta impedir que o Windows desligue/bloqueie o adaptador enquanto
    o programa estiver rodando. Devolve snapshot do estado original.

    Acoes:
      - Set-NetAdapterPowerManagement -AllowComputerToTurnOffDevice Disabled
      - Enable-NetAdapter se estiver Disabled (so se possivel)

    NAO ha garantia absoluta: GPO, drivers OEM, politicas de bateria
    (quando em modo de energia agressivo) e Mobility Center podem
    sobrescrever. O programa reaplica em loop (nic_guard) e logga quando
    detecta reversao.
    """
    snapshot: dict[str, Any] = {"name": adapter_name}
    if not is_windows():
        return snapshot

    pm = obter_power_management(adapter_name)
    if pm:
        snapshot["pm"] = pm
        allow = str(pm.get("AllowComputerToTurnOffDevice", "")).lower()
        if allow in ("enabled", "true", "1"):
            script = (
                f"try {{ Set-NetAdapterPowerManagement -Name "
                f"'{adapter_name}' "
                f"-AllowComputerToTurnOffDevice Disabled "
                f"-NoRestart -ErrorAction Stop; 'OK' }} catch "
                f"{{ $_.Exception.Message }}"
            )
            out = _run_powershell(script).strip()
            if out == "OK":
                log(f"[NIC-LOCK] AllowComputerToTurnOffDevice=Disabled "
                    f"em '{adapter_name}'.")
                snapshot["pm_modified"] = True
            else:
                log(f"[NIC-LOCK] Falha ao alterar PowerManagement: {out}",
                    logging.WARNING)

    status = _status_adaptador(adapter_name)
    snapshot["status"] = status
    if status and status.lower() == "disabled":
        script = (
            f"try {{ Enable-NetAdapter -Name '{adapter_name}' "
            f"-Confirm:$false -ErrorAction Stop; 'OK' }} catch "
            f"{{ $_.Exception.Message }}"
        )
        out = _run_powershell(script).strip()
        if out == "OK":
            log(f"[NIC-LOCK] Reativado '{adapter_name}' (estava Disabled).")
            snapshot["enabled_by_lock"] = True
        else:
            log(f"[NIC-LOCK] Falha ao reativar: {out}", logging.WARNING)

    return snapshot


def restaurar_nic(snapshot: dict) -> None:
    """Restaura o estado da NIC capturado por bloquear_nic()."""
    if not snapshot:
        return
    name = snapshot.get("name")
    if not name or not is_windows():
        return

    with _NIC_LOCK_LOCK:
        try:
            if snapshot.get("pm_modified") and snapshot.get("pm"):
                allow = _ps_bool_arg(
                    snapshot["pm"].get("AllowComputerToTurnOffDevice", "Disabled"))
                script = (
                    f"try {{ Set-NetAdapterPowerManagement -Name '{name}' "
                    f"-AllowComputerToTurnOffDevice {allow} -NoRestart "
                    f"-ErrorAction Stop; 'OK' }} catch "
                    f"{{ $_.Exception.Message }}"
                )
                out = _run_powershell(script).strip()
                if out == "OK":
                    log(f"[NIC-LOCK] Estado original restaurado em '{name}' "
                        f"(AllowComputerToTurnOffDevice={allow}).")
                else:
                    log(f"[NIC-LOCK] Falha ao restaurar PowerManagement: "
                        f"{out}", logging.WARNING)
        except Exception as e:  # noqa: BLE001
            log(f"[NIC-LOCK] Erro na restauracao: {e}", logging.WARNING)


def nic_guard(adapter_name: str, snapshot: dict,
              intervalo: float = 10.0) -> None:
    """
    Thread guardia: periodicamente verifica se o lock foi desfeito
    (energia ou interface desabilitada) e reaplica.
    """
    while not STOP_EVENT.is_set():
        try:
            with _NIC_LOCK_LOCK:
                # 1) Reativa se foi Disabled
                status = _status_adaptador(adapter_name)
                if status and status.lower() == "disabled":
                    log(f"[NIC-GUARD] '{adapter_name}' foi Disabled "
                        f"externamente. Re-habilitando.",
                        logging.WARNING)
                    _run_powershell(
                        f"try {{ Enable-NetAdapter -Name '{adapter_name}' "
                        f"-Confirm:$false -ErrorAction Stop }} catch {{}}"
                    )
                # 2) Re-aplica politica de energia
                pm = obter_power_management(adapter_name)
                if pm:
                    allow = str(pm.get("AllowComputerToTurnOffDevice",
                                       "")).lower()
                    if allow in ("enabled", "true", "1"):
                        log(f"[NIC-GUARD] AllowComputerToTurnOffDevice "
                            f"voltou a Enabled. Re-desabilitando.",
                            logging.WARNING)
                        _run_powershell(
                            f"try {{ Set-NetAdapterPowerManagement -Name "
                            f"'{adapter_name}' "
                            f"-AllowComputerToTurnOffDevice Disabled "
                            f"-NoRestart -ErrorAction Stop }} catch {{}}"
                        )
                        snapshot["pm_modified"] = True
        except Exception as e:  # noqa: BLE001
            LOGGER.debug("nic_guard erro: %s", e)
        STOP_EVENT.wait(intervalo)


# ========================================================================
# 10.57. IOMMU GUARD - monitora e tenta manter o DMA Remapping da NIC
#                     no estado atual (atualmente DESABILITADO).
# ========================================================================
# IMPORTANTE / HONESTIDADE:
#   - IOMMU em si (Intel VT-d / AMD-Vi) e um recurso de firmware (UEFI).
#     Nenhum programa em user space pode ligar/desligar IOMMU - isso
#     fica no setup da BIOS.
#   - No Windows, o que uma aplicacao consegue observar/mexer sao:
#       * O status geral de VBS/DeviceGuard
#         (Win32_DeviceGuard: VirtualizationBasedSecurityStatus,
#          SecurityServicesConfigured, SecurityServicesRunning).
#       * A politica de "DMA Remapping" POR DISPOSITIVO PCIe
#         (DEVPKEY_Device_DmaRemappingPolicy), armazenada em
#         HKLM\SYSTEM\CurrentControlSet\Enum\<PnPInstance>\Device
#         Parameters\DmaRemappingCompatible (DWORD 0=Disabled, 1=Enabled).
#   - Este modulo tira uma "foto" do estado atual (snapshot), monitora
#     mudancas periodicamente, loga alertas e - quando permitido - tenta
#     reverter a chave de registro do dispositivo para o valor original.
#     Mudancas em DeviceGuard/VBS so entram em vigor APOS reboot, entao
#     reverter em runtime nao desfaz um reboot que ja aconteceu com
#     outra politica.

_IOMMU_SNAPSHOT: dict[str, Any] = {}
_IOMMU_LOCK = threading.Lock()


def _ler_pnp_instance(adapter_name: str) -> str | None:
    """Retorna o PnPDeviceID (ex: PCI\\VEN_8086&DEV_153B\\...) do adaptador."""
    if not is_windows():
        return None
    script = (
        f"try {{ (Get-NetAdapter -Name '{adapter_name}' "
        "-IncludeHidden -ErrorAction Stop).PnPDeviceID }} catch { '' }"
    )
    out = _run_powershell(script).strip()
    return out or None


def ler_estado_iommu(adapter_name: str | None) -> dict:
    """
    Captura:
      - device_guard: VBS/HVCI status (sistema todo).
      - dma_remapping_policy: DEVPKEY_Device_DmaRemappingPolicy do adaptador.
      - dma_remapping_compat: valor em HKLM...Device Parameters\\
        DmaRemappingCompatible, se existir.
      - pnp_id: PnPDeviceID do adaptador (necessario para reverter via reg).
    Retorna {} se nao for Windows ou se falhar.
    """
    estado: dict[str, Any] = {}
    if not is_windows():
        return estado

    # Device Guard / VBS (sistema)
    script = (
        "try { Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace 'root\\Microsoft\\Windows\\DeviceGuard' "
        "-ErrorAction Stop | Select-Object "
        "VirtualizationBasedSecurityStatus,"
        "SecurityServicesConfigured,SecurityServicesRunning,"
        "AvailableSecurityProperties | ConvertTo-Json -Compress "
        "} catch { '' }"
    )
    raw = _run_powershell(script).strip()
    if raw:
        try:
            estado["device_guard"] = json.loads(raw)
        except json.JSONDecodeError:
            pass

    if not adapter_name:
        return estado

    pnp = _ler_pnp_instance(adapter_name)
    if pnp:
        estado["pnp_id"] = pnp

    # Politica PnP (DEVPKEY_Device_DmaRemappingPolicy)
    if pnp:
        pnp_escaped = pnp.replace("'", "''")
        script = (
            f"try {{ $p = Get-PnpDeviceProperty -InstanceId '{pnp_escaped}' "
            "-KeyName 'DEVPKEY_Device_DmaRemappingPolicy' "
            "-ErrorAction Stop; $p.Data } catch { '' }"
        )
        raw = _run_powershell(script).strip()
        if raw:
            # Data costuma ser int (0=Disabled, 1=Enabled)
            try:
                estado["dma_remapping_policy"] = int(raw)
            except ValueError:
                estado["dma_remapping_policy"] = raw

        # Chave de registro Device Parameters\DmaRemappingCompatible
        reg_path = (f"HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\{pnp}"
                    "\\Device Parameters")
        reg_escaped = reg_path.replace("'", "''")
        script = (
            f"try {{ (Get-ItemProperty -Path '{reg_escaped}' "
            "-Name DmaRemappingCompatible -ErrorAction Stop)"
            ".DmaRemappingCompatible } catch { '' }"
        )
        raw = _run_powershell(script).strip()
        if raw:
            try:
                estado["dma_remapping_compat"] = int(raw)
                estado["dma_remapping_regpath"] = reg_path
            except ValueError:
                estado["dma_remapping_compat"] = raw

    return estado


def _descrever_vbs(code: Any) -> str:
    """VirtualizationBasedSecurityStatus: 0=Off, 1=Configured but off, 2=Running."""
    try:
        c = int(code)
    except (TypeError, ValueError):
        return str(code)
    return {0: "Off", 1: "Configured but not running", 2: "Running"}.get(
        c, str(c))


def _descrever_dma(code: Any) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return str(code)
    return {0: "Disabled", 1: "Enabled"}.get(c, str(c))


def _reverter_dma_remapping(adapter: dict, snapshot: dict,
                            valor_desejado: int) -> bool:
    """
    Tenta restaurar a chave de registro
    HKLM\\...Device Parameters\\DmaRemappingCompatible para `valor_desejado`.

    Devolve True em caso de sucesso. Exige Administrador. A mudanca so
    toma efeito depois que o dispositivo for re-enumerado (geralmente
    reboot ou Disable/Enable da NIC via Device Manager). O programa NAO
    desabilita a NIC automaticamente so para re-enumerar - isso cortaria
    o keep-alive.
    """
    reg_path = snapshot.get("dma_remapping_regpath")
    if not reg_path or not is_admin() or not is_windows():
        return False
    reg_escaped = reg_path.replace("'", "''")
    script = (
        f"try {{ New-ItemProperty -Path '{reg_escaped}' "
        f"-Name DmaRemappingCompatible -Value {int(valor_desejado)} "
        f"-PropertyType DWord -Force -ErrorAction Stop | Out-Null; "
        f"'OK' }} catch {{ $_.Exception.Message }}"
    )
    out = _run_powershell(script).strip()
    if out == "OK":
        return True
    log(f"[IOMMU-GUARD] Falha ao reverter DmaRemappingCompatible: {out}",
        logging.WARNING)
    return False


def imprimir_estado_iommu(adapter_name: str, estado: dict) -> None:
    print("\nIOMMU / DMA Remapping - snapshot inicial:")
    print("-" * 50)
    dg = estado.get("device_guard") or {}
    vbs = dg.get("VirtualizationBasedSecurityStatus")
    print(f"  VBS (sistema):             {_descrever_vbs(vbs)}")
    print(f"  SecurityServicesConfigured: {dg.get('SecurityServicesConfigured')}")
    print(f"  SecurityServicesRunning:    {dg.get('SecurityServicesRunning')}")
    pol = estado.get("dma_remapping_policy")
    if pol is not None:
        print(f"  DMA Remapping Policy (PnP): {_descrever_dma(pol)}  "
              f"[{pol}]")
    cmp = estado.get("dma_remapping_compat")
    if cmp is not None:
        print(f"  DmaRemappingCompatible (reg): {_descrever_dma(cmp)}  "
              f"[{cmp}]")
    if estado.get("pnp_id"):
        print(f"  PnPDeviceID: {estado['pnp_id']}")
    print("-" * 50)
    print("  (IOMMU em si e controlado pela UEFI; este programa so")
    print("   monitora e tenta manter a politica DO DISPOSITIVO.)")


def iommu_watchdog(adapter: dict, snapshot: dict,
                   intervalo: float = 20.0,
                   tentar_reverter: bool = True) -> None:
    """
    Thread guardia do IOMMU/DMA Remapping da NIC.
    - Se detectar mudanca na politica do dispositivo, loga alerta.
    - Se `tentar_reverter`, reescreve a chave de registro para o
      valor original (so entra em vigor na proxima re-enumeracao).
    - Se detectar mudanca em VBS/DeviceGuard, loga alerta (sem acao -
      exige reboot).
    """
    orig_dma = snapshot.get("dma_remapping_compat")
    if orig_dma is None:
        orig_dma = snapshot.get("dma_remapping_policy")
    orig_dg = (snapshot.get("device_guard") or {}).get(
        "VirtualizationBasedSecurityStatus")

    while not STOP_EVENT.is_set():
        try:
            with _IOMMU_LOCK:
                atual = ler_estado_iommu(adapter["name"])

                # 1) DMA Remapping da NIC
                dma_now = atual.get("dma_remapping_compat")
                if dma_now is None:
                    dma_now = atual.get("dma_remapping_policy")
                if (orig_dma is not None and dma_now is not None
                        and dma_now != orig_dma):
                    log(f"[IOMMU-GUARD] DMA Remapping do dispositivo "
                        f"mudou: {_descrever_dma(orig_dma)} -> "
                        f"{_descrever_dma(dma_now)}.", logging.WARNING)
                    if tentar_reverter and is_admin():
                        if _reverter_dma_remapping(
                                adapter, snapshot, int(orig_dma)):
                            log(f"[IOMMU-GUARD] Registro revertido para "
                                f"{_descrever_dma(orig_dma)} "
                                f"(efetivo apos re-enumeracao do "
                                f"dispositivo).")

                # 2) VBS / DeviceGuard do sistema
                dg_now = (atual.get("device_guard") or {}).get(
                    "VirtualizationBasedSecurityStatus")
                if (orig_dg is not None and dg_now is not None
                        and dg_now != orig_dg):
                    log(f"[IOMMU-GUARD] VBS mudou: "
                        f"{_descrever_vbs(orig_dg)} -> "
                        f"{_descrever_vbs(dg_now)}. Mudancas de VBS "
                        f"so tomam efeito apos reboot.",
                        logging.WARNING)
        except Exception as e:  # noqa: BLE001
            LOGGER.debug("iommu_watchdog: %s", e)
        STOP_EVENT.wait(intervalo)


# ========================================================================
# 10.6. DIAGNOSTICO (executado antes do AdaptiveKeepAlive)
# ========================================================================
def executar_diagnostico(args: argparse.Namespace, adapter: dict,
                        scapy_iface: str | None,
                        src_ip: str | None) -> bool:
    """
    Executa um diagnostico completo e imprime relatorio. Retorna True
    se nao houver nenhum item 'FAIL'. 'WARN' nao bloqueia a execucao.
    """
    results: list[tuple[str, str, str]] = []

    def chk(nome: str, status: str, detalhe: str = "") -> None:
        results.append((nome, status, detalhe))

    # Scapy
    chk("Scapy", "OK" if SCAPY_OK else "FAIL",
        "" if SCAPY_OK else "pip install scapy")

    # Npcap: podemos listar interfaces?
    if SCAPY_OK:
        try:
            ifaces = get_if_list()
            if ifaces:
                chk("Npcap", "OK", f"{len(ifaces)} interfaces visiveis")
            else:
                chk("Npcap", "FAIL",
                    "nenhuma interface - reinstale Npcap "
                    "(WinPcap API-compatible)")
        except Exception as e:  # noqa: BLE001
            chk("Npcap", "FAIL", str(e))
    else:
        chk("Npcap", "SKIP", "scapy indisponivel")

    # Interface
    if adapter:
        chk("Interface", "OK", adapter["description"])
    else:
        chk("Interface", "FAIL", "adaptador nao selecionado")

    # Link
    if adapter:
        st = (adapter["status"] or "").strip()
        if st.lower() == "up":
            chk("Link", "OK", st)
        elif st.lower() in ("down", "disconnected"):
            chk("Link", "WARN", st)
        elif st.lower() == "disabled":
            chk("Link", "WARN", "interface administrativamente desabilitada")
        else:
            chk("Link", "WARN", st or "desconhecido")

    # IPv4 / MAC / ifIndex
    chk("IPv4", "OK" if src_ip else "WARN", src_ip or "sem IPv4")
    if adapter:
        chk("MAC", "OK" if adapter["mac"] else "WARN",
            adapter["mac"] or "sem MAC")
        chk("ifIndex", "OK" if adapter["ifindex"] else "WARN",
            str(adapter["ifindex"]))

    # Conectividade
    tp = args.target_port or args.port or 80
    ok, dt = _probe_tcp(src_ip, args.target, tp, timeout=2.0)
    if ok:
        chk("Connectivity", "OK",
            f"TCP {args.target}:{tp} ok ({dt:.0f}ms)")
    else:
        chk("Connectivity", "WARN",
            f"TCP {args.target}:{tp} falhou (adaptativo usara backoff)")

    # Power management
    if adapter:
        pm = obter_power_management(adapter["name"])
        if pm is None:
            chk("Power Management", "SKIP", "sem dados")
        else:
            allow = str(pm.get("AllowComputerToTurnOffDevice", "")).lower()
            if allow in ("enabled", "true", "1"):
                chk("Power Management", "WARN",
                    "AllowComputerToTurnOffDevice=Enabled "
                    "- Windows pode desligar a NIC")
            else:
                chk("Power Management", "OK",
                    f"AllowComputerToTurnOffDevice="
                    f"{pm.get('AllowComputerToTurnOffDevice')}")

    # Pode enviar? Faz um envio ARP minimo (nao e flood).
    if SCAPY_OK and scapy_iface and adapter:
        try:
            dummy = (Ether(src=adapter["mac"] or "02:00:00:00:00:01",
                           dst=MAC_BROADCAST)
                     / ARP(op=1, hwsrc=adapter["mac"] or "02:00:00:00:00:01",
                           psrc=src_ip or "0.0.0.0",
                           pdst=args.target))
            sendp(dummy, iface=scapy_iface, verbose=False)
            chk("Can send", "OK", f"via {scapy_iface}")
        except Exception as e:  # noqa: BLE001
            chk("Can send", "FAIL", str(e))

    # Relatorio
    print("\nETHKEEPALIVE DIAGNOSTIC")
    print("-" * 50)
    tags = {"OK": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]",
            "SKIP": "[SKIP]"}
    for nome, status, detalhe in results:
        linha = f"{tags[status]} {nome}"
        if detalhe:
            linha += f" - {detalhe}"
        print(linha)
    print("-" * 50)
    return not any(s == "FAIL" for _, s, _ in results)


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
            "  python ethkeepalive.py -d 2 --anti-idle\n"
            "  python ethkeepalive.py -d 2 --keepalive-mode aggressive "
            "--jitter 0.5\n"
            "  python ethkeepalive.py -d 2 --diagnostic\n"
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

    # ----- AdaptiveKeepAlive -----
    g = p.add_argument_group("AdaptiveKeepAlive")
    g.add_argument("--keepalive-mode", dest="keepalive_mode",
                   choices=["basic", "adaptive", "aggressive"],
                   default="basic",
                   help="basic=comportamento classico (so --proto); "
                        "adaptive=alterna ICMP/TCP/HTTP/ARP com testes "
                        "reais; aggressive=encurta intervalo quando ha "
                        "silencio prolongado (sempre dentro dos limites)")
    g.add_argument("--anti-idle", dest="anti_idle", action="store_true",
                   help="Atalho: ativa --keepalive-mode adaptive e roda "
                        "diagnostico antes de iniciar")
    g.add_argument("--diagnostic", action="store_true",
                   help="Executa diagnostico completo e sai")
    g.add_argument("--jitter", type=float, default=0.3,
                   help="Variacao aleatoria do intervalo em segundos "
                        "(padrao: 0.3)")
    g.add_argument("--min-interval", dest="min_interval", type=float,
                   default=1.0,
                   help=f"Intervalo minimo entre testes (padrao: 1.0, "
                        f"piso de seguranca: {SAFETY_MIN_INTERVAL})")
    g.add_argument("--max-interval", dest="max_interval", type=float,
                   default=30.0,
                   help="Intervalo maximo entre testes "
                        "(padrao: 30, teto: 300)")
    g.add_argument("--target-port", dest="target_port", type=int,
                   default=80,
                   help="Porta TCP de destino para testes do "
                        "adaptativo (padrao: 80)")
    g.add_argument("--http-host", dest="http_host", type=str, default=None,
                   help="Header Host das requisicoes HTTP "
                        "(padrao: o IP de --target)")
    g.add_argument("--http-url", dest="http_url", type=str, default="/",
                   help="Caminho usado nos HTTP GET/HEAD/POST "
                        "(padrao: /)")
    g.add_argument("--tcp-mode", dest="tcp_mode",
                   choices=["short", "keep-alive"], default="short",
                   help="Reaproveitar socket TCP entre ciclos "
                        "(padrao: short)")
    g.add_argument("--lock-nic", dest="lock_nic", action="store_true",
                   help="Tenta impedir que o Windows desative/desligue "
                        "a NIC enquanto o programa roda (desativa "
                        "AllowComputerToTurnOffDevice e re-habilita se "
                        "Disabled). Restaura o estado original ao sair. "
                        "Exige Administrador. NAO sobrepoe GPO/drivers "
                        "OEM; os avisos continuam valendo.")
    g.add_argument("--watch-iommu", dest="watch_iommu", action="store_true",
                   help="Monitora e tenta manter a politica de DMA "
                        "Remapping do dispositivo PCIe no estado atual "
                        "(ex.: Disabled). Reverte a chave de registro se "
                        "algo tentar alterar. IOMMU em si e configurado "
                        "em UEFI/BIOS e NAO pode ser bloqueado por "
                        "programa em user space; o programa so alerta "
                        "sobre mudancas de VBS.")

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
    def hms(s: float) -> str:
        s = int(s)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"
    started = STATS.get("started_at")
    dur = (time.time() - started) if started else 0.0
    print("\n" + "=" * 60)
    print("ETHKEEPALIVE STATISTICS")
    print("=" * 60)
    print(f"Tempo ativo:          {hms(dur)}")
    print(f"Pacotes enviados:     {STATS['pkts_sent']:,}")
    print(f"  - HTTP:             {STATS['pkts_http']:,}")
    print(f"  - ARP:              {STATS['pkts_arp']:,}")
    print(f"  - DHCP:             {STATS['pkts_dhcp']:,}")
    print(f"  - ICMP:             {STATS['icmp_sent']:,}")
    print(f"Bytes enviados:       {STATS['bytes_sent']:,} B")
    print(f"Testes ICMP:          {STATS['ok_icmp'] + STATS['fail_icmp']:,}"
          f" (ok {STATS['ok_icmp']:,} / falha {STATS['fail_icmp']:,})")
    print(f"Conexoes TCP:         {STATS['ok_tcp'] + STATS['fail_tcp']:,}"
          f" (ok {STATS['ok_tcp']:,} / falha {STATS['fail_tcp']:,})")
    print(f"HTTP requests:        {STATS['http_sent']:,}"
          f" (ok {STATS['ok_http']:,} / falha {STATS['fail_http']:,})")
    print(f"ARP probes:           {STATS['arp_sent']:,}"
          f" (ok {STATS['ok_arp']:,} / falha {STATS['fail_arp']:,})")
    print(f"Requisicoes no HTTP fake: {STATS['http_requests']:,}")
    print(f"Mudancas de estado:   {STATS['state_changes']:,}")
    print(f"Quedas/Recuperacoes:  {STATS['reconnects']:,}")
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
          f"mac={adapter['mac']})")

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

    # IPs/MACs do adaptador - usados para o binding da camada adaptativa
    src_ip = _guess_local_ip(adapter)
    src_ipv6 = _guess_local_ipv6(adapter)
    try:
        src_mac = get_if_hwaddr(scapy_iface)
    except Exception:
        src_mac = adapter["mac"] or "02:00:00:00:00:01"

    imprimir_cabecalho_interface(adapter, scapy_iface, src_ip, src_mac,
                                 src_ipv6)
    if not src_ip:
        log("Sem IPv4 detectado - o binding de sockets TCP/HTTP nao pode "
            "ser garantido para esta NIC. O envio raw (ICMP/ARP via Scapy) "
            "continua restrito a interface escolhida.", logging.WARNING)

    # Modo diagnostico (encerra apos relatorio)
    if args.diagnostic:
        ok = executar_diagnostico(args, adapter, scapy_iface, src_ip)
        return 0 if ok else 5

    # Resolver modo efetivo (--anti-idle e um atalho)
    mode = args.keepalive_mode
    if args.anti_idle and mode == "basic":
        mode = "adaptive"
    args.keepalive_mode = mode

    adaptive = mode in ("adaptive", "aggressive")
    if adaptive:
        print()
        if not executar_diagnostico(args, adapter, scapy_iface, src_ip):
            log("Diagnostico falhou. Encerrando.", logging.ERROR)
            return 5
        pm = obter_power_management(adapter["name"]) or {}
        if str(pm.get("AllowComputerToTurnOffDevice", "")).lower() in (
                "enabled", "true", "1"):
            log("A interface esta sendo afetada por gerenciamento de "
                "energia. Trafego de rede nao garante que o Windows "
                "mantera o dispositivo ligado. Corrija em "
                "Gerenciador de Dispositivos > Propriedades do adaptador "
                "> Gerenciamento de energia (ou "
                "Set-NetAdapterPowerManagement -AllowComputerToTurnOffDevice "
                "Disabled).", logging.WARNING)

    STATS["started_at"] = time.time()
    threads: list[threading.Thread] = []
    nic_snapshot: dict = {}
    iommu_snapshot: dict = {}

    # IOMMU WATCH (opcional): monitora/trava DMA Remapping do dispositivo
    if args.watch_iommu:
        iommu_snapshot = ler_estado_iommu(adapter["name"])
        if iommu_snapshot:
            imprimir_estado_iommu(adapter["name"], iommu_snapshot)
            if not is_admin():
                log("[IOMMU-GUARD] Sem Administrador: so monitorar "
                    "mudancas, sem reverter.", logging.WARNING)
            t_iommu = threading.Thread(
                target=iommu_watchdog,
                args=(adapter, iommu_snapshot),
                kwargs={"tentar_reverter": is_admin()},
                daemon=True, name="iommu-guard")
            t_iommu.start()
            threads.append(t_iommu)
        else:
            log("[IOMMU-GUARD] Nao consegui ler estado inicial. "
                "Watch desabilitado.", logging.WARNING)

    # NIC LOCK (opcional): tenta impedir Windows de desligar/bloquear a NIC
    if args.lock_nic:
        if not is_windows():
            log("--lock-nic ignorado: nao estamos em Windows.",
                logging.WARNING)
        elif not is_admin():
            log("--lock-nic ignorado: precisa de Administrador para "
                "alterar PowerManagement/Enable-NetAdapter.",
                logging.ERROR)
        else:
            log("[NIC-LOCK] Tentando bloquear desativacao da NIC "
                "enquanto o programa roda...")
            nic_snapshot = bloquear_nic(adapter["name"])
            t_guard = threading.Thread(
                target=nic_guard,
                args=(adapter["name"], nic_snapshot),
                daemon=True, name="nic-guard")
            t_guard.start()
            threads.append(t_guard)

    # Servidor HTTP fake (compartilhado por ambos os modos)
    if not args.sem_http:
        t_http = threading.Thread(target=servidor_http_fake,
                                  args=(args.port,), daemon=True,
                                  name="http-fake")
        t_http.start()
        threads.append(t_http)
    else:
        log("Servidor HTTP fake desativado (--sem-http).")

    if adaptive:
        # Modo adaptativo: AdaptiveKeepAlive + watchdog acoplado
        aka = AdaptiveKeepAlive(args, adapter, scapy_iface, src_ip, src_mac)
        t_wd = threading.Thread(target=watchdog_interface_adaptive,
                                args=(adapter["name"], aka),
                                daemon=True, name="watchdog")
        t_wd.start()
        threads.append(t_wd)
        t_tx = threading.Thread(target=aka.run, daemon=True,
                                name="adaptive-keepalive")
        t_tx.start()
        threads.append(t_tx)
    else:
        # Modo classico: watchdog simples + gerar_trafego
        t_wd = threading.Thread(target=watchdog_interface,
                                args=(adapter["name"],),
                                daemon=True, name="watchdog")
        t_wd.start()
        threads.append(t_wd)
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
        if nic_snapshot:
            restaurar_nic(nic_snapshot)
        _resumo_estatisticas()
    return 0


if __name__ == "__main__":
    sys.exit(main())
