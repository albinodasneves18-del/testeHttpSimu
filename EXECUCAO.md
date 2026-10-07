# EXECUÇÃO — passo a passo

Este guia mostra como rodar o **EthKeepAlive** depois de instalado
(ver [INSTALL.md](INSTALL.md)).

---

## 1. Escolha a forma de rodar

Existem três formas, da mais simples para a mais avançada:

| Forma                     | Quando usar                                               |
|---------------------------|-----------------------------------------------------------|
| `ethkeepalive.bat`        | Duplo-clique no Explorer. Faz tudo com defaults seguros.  |
| `cmd` como Administrador  | Controle total das flags do CLI.                          |
| Agendado (Scheduler)      | Rodar automaticamente no logon ou boot da máquina.        |

---

## 2. Primeira execução — listar adaptadores

**Objetivo:** descobrir o `ID` do adaptador que você quer manter ativo.

### Via BAT

Duplo-clique em **`ethkeepalive-listar.bat`**.

### Via `cmd`

```
cd C:\tools\ethkeepalive
python ethkeepalive.py --listar
```

Saída típica:

```
---------------------------------------------------------------------------
ID   Status        Nome                Descricao                                   MAC                  LinkSpeed     ifIndex
---------------------------------------------------------------------------
1    Up            Ethernet            Intel(R) Ethernet Connection I219-V         a1:b2:c3:d4:e5:f6    1 Gbps        3
2    Disconnected  Ethernet 2          Realtek USB GbE Family Controller           11:22:33:44:55:66    -             7
3    Up            Wi-Fi               Intel(R) Wi-Fi 6 AX201 160MHz               00:11:22:33:44:55    866 Mbps      11
---------------------------------------------------------------------------
```

**Anote o `ID` da linha correta** (coluna `ID`). No exemplo acima, para
manter o adaptador USB Realtek ativo você usaria `-d 2`.

---

## 3. Diagnóstico (sempre antes do primeiro uso real)

**Objetivo:** verificar se Scapy, Npcap, link, IPv4, MAC e conectividade
estão prontos **sem** disparar tráfego contínuo.

```
python ethkeepalive.py -d 2 --diagnostic
```

Saída típica:

```
Interface selecionada:
  Nome:        Ethernet 2
  Descricao:   Realtek USB GbE Family Controller
  ifIndex:     7
  IPv4:        192.168.1.50
  IPv6:        (nao detectado)
  MAC:         11:22:33:44:55:66
  LinkSpeed:   1 Gbps
  Scapy iface: \Device\NPF_{GUID}
O trafego sera associado a esta interface (bind no IPv4 + envio raw).

ETHKEEPALIVE DIAGNOSTIC
--------------------------------------------------
[OK]   Scapy
[OK]   Npcap - 25 interfaces visiveis
[OK]   Interface - Realtek USB GbE Family Controller
[OK]   Link - Up
[OK]   IPv4 - 192.168.1.50
[OK]   MAC - 11:22:33:44:55:66
[OK]   ifIndex - 7
[OK]   Connectivity - TCP 192.168.1.1:80 ok (3ms)
[WARN] Power Management - AllowComputerToTurnOffDevice=Enabled
[OK]   Can send - via \Device\NPF_{GUID}
--------------------------------------------------
```

Se aparecer **FAIL**, resolva antes de prosseguir
(ver [INSTALL.md](INSTALL.md) → *Troubleshooting*).

Se aparecer **WARN** em *Power Management*, considere usar `--lock-nic`
(passo 5).

---

## 4. Execução recomendada (anti-idle)

**Objetivo:** manter o adaptador ativo com tráfego moderado e variado
(ICMP, TCP, HTTP GET/HEAD/POST, ARP) + servidor HTTP fake local.

### Via BAT (mais fácil)

Duplo-clique em **`ethkeepalive.bat`**. Ele executa, por padrão:

```
python ethkeepalive.py --anti-idle --lock-nic
```

### Via `cmd` (controle total)

```
cd C:\tools\ethkeepalive
python ethkeepalive.py -d 2 --anti-idle --lock-nic
```

O que você verá:

```
STATE: STARTING -> HEALTHY
AdaptiveKeepAlive iniciado (modo=adaptive, base=2.00s, jitter=0.3s, ...)
[ICMP] ok -> 192.168.1.1
[TCP] connect 192.168.1.1:80 (2ms)
[HTTP GET] HTTP/1.1 200 OK
[HTTP HEAD] HTTP/1.1 200 OK
[HTTP POST] HTTP/1.1 200 OK
[ARP] reply recebido de 192.168.1.1
[KEEPALIVE] Estado: HEALTHY | Ultima atividade: 1.4s | Ultimo sucesso: 1.4s | intervalo: 2.00s
...
```

**Para encerrar:** `Ctrl+C`. O programa restaura o estado da NIC
(se `--lock-nic` estiver ativo) e imprime o resumo:

```
ETHKEEPALIVE STATISTICS
============================================================
Tempo ativo:          00:12:34
Pacotes enviados:     1.231
  - HTTP:             410
  - ARP:              123
  - ICMP:             205
Testes ICMP:          205 (ok 203 / falha 2)
Conexoes TCP:         204 (ok 204 / falha 0)
HTTP requests:        615 (ok 613 / falha 2)
...
```

---

## 5. Trava total — `--lock-nic` + `--watch-iommu`

**Objetivo:** o Windows **não** deve conseguir desativar nem bloquear a
NIC enquanto o programa está rodando, e nenhum software deve conseguir
alterar a política de DMA Remapping/IOMMU do dispositivo
(hoje `Disabled`).

```
python ethkeepalive.py -d 2 --anti-idle --lock-nic --watch-iommu
```

Isso ativa:

- `--lock-nic` – desabilita `AllowComputerToTurnOffDevice` e reaplica
  a cada 10 s; re-habilita a NIC se alguém a `Disable` por fora;
  restaura o estado original ao sair.
- `--watch-iommu` – tira foto da chave de registro
  `HKLM\SYSTEM\CurrentControlSet\Enum\<PnP>\Device Parameters\
  DmaRemappingCompatible` e do VBS do sistema; a cada 20 s compara.
  Se mudar, loga aviso e reverte a chave para o valor original (efeito
  após re-enumeração do dispositivo).

> ⚠️ **O que esse modo NÃO faz** — honestidade total:
> - **Não** liga/desliga IOMMU no firmware (isso é UEFI).
> - **Não** sobrepõe GPO corporativa / HVCI / Credential Guard.
> - Se algum software já estiver manipulando a política antes do boot,
>   só na próxima inicialização o watch verá a diferença.
> - Mudanças em VBS/DeviceGuard só tomam efeito depois de reboot — o
>   programa apenas **alerta**.

---

## 6. Modos avançados do CLI

### Alterar protocolo do modo clássico

```
python ethkeepalive.py -d 2 --proto mixed -n 1
python ethkeepalive.py -d 2 --proto arp
python ethkeepalive.py -d 2 --proto dhcp
```

### Modo agressivo (acelera após silêncio)

```
python ethkeepalive.py -d 2 --keepalive-mode aggressive --jitter 0.5 \
  --min-interval 1 --max-interval 60
```

### Alvo HTTP real

```
python ethkeepalive.py -d 2 --anti-idle ^
  --target 192.168.1.1 --target-port 80 ^
  --http-host router.local --http-url /ping
```

### Rodar em background (sem HTTP fake, só log)

```
python ethkeepalive.py -d 2 --anti-idle --sem-http --quiet ^
  --log C:\logs\ethkeepalive.log
```

### Reproduzir um `.pcap` em loop

```
python ethkeepalive.py -d 2 --pcap captura.pcap
```

---

## 7. Agendar no logon ou boot (opcional)

Para iniciar automaticamente quando o usuário entra na máquina:

1. Abra `taskschd.msc` (Agendador de Tarefas).
2. **Criar Tarefa** (não "Criar Tarefa Básica").
3. Aba **Geral**:
   - Nome: `EthKeepAlive`.
   - Marque **Executar com privilégios mais altos**.
   - Configurar para **Windows 10/11**.
4. Aba **Disparadores** → **Novo** → *Ao fazer logon* (ou *Ao iniciar*).
5. Aba **Ações** → **Novo**:
   - Programa: `C:\tools\ethkeepalive\ethkeepalive.bat`.
   - Argumentos: `-d 2 --anti-idle --lock-nic --watch-iommu --quiet --log C:\logs\ethkeepalive.log`.
   - Iniciar em: `C:\tools\ethkeepalive`.
6. Aba **Condições**:
   - Desmarque "Iniciar a tarefa somente se o computador estiver conectado à energia".
7. Aba **Configurações**:
   - Permita a tarefa ser executada sob demanda.
   - "Se a tarefa falhar, reiniciar a cada: 1 minuto; tentar reiniciar até 3 vezes".
8. Salve.

> 💡 O console não vai aparecer no logon — o programa fica em segundo
> plano gravando no arquivo de log informado. Para enxergar logs em
> tempo real, use `Get-Content C:\logs\ethkeepalive.log -Wait` em
> outro terminal.

---

## 8. Fluxograma de decisão

```
┌─────────────────────────────────────────────────────┐
│ Instalei tudo (INSTALL.md)                          │
└─────────────────────────────────────────────────────┘
                       │
                       ▼
     ┌────────────────────────────────────┐
     │ ethkeepalive-listar.bat            │
     │   → anote o ID do adaptador        │
     └────────────────────────────────────┘
                       │
                       ▼
     ┌────────────────────────────────────┐
     │ --diagnostic                       │
     │   → tudo OK? FAIL? WARN?           │
     └────────────────────────────────────┘
            │                   │
            │ OK                │ FAIL
            ▼                   ▼
     ┌─────────────┐    ┌─────────────────────┐
     │ --anti-idle │    │ Corrigir conforme   │
     │   + lock    │    │ INSTALL.md          │
     │   + watch   │    └─────────────────────┘
     │   iommu     │
     └─────────────┘
            │
            ▼
         Ctrl+C
            │
            ▼
     ┌─────────────────────────┐
     │ Restaura estado + stats │
     └─────────────────────────┘
```

---

## 9. NIC sem IPv4 configurado — modo `--raw-only`

Se a NIC que você quer manter ativa **não tem IP configurado** (porta
secundária de uma placa dual-port, NIC sem DHCP, NIC em VLAN sem IP, ou
qualquer caso onde `IPv4: (nao detectado)` aparece no cabeçalho), os
testes TCP/HTTP via socket vão **sempre falhar** — não porque a NIC
está morta, mas porque o Windows roteia esses sockets por outra
interface (a que tem rota default).

**O que acontece:**

- `ICMP sem resposta` → não há rota IP para o alvo via essa NIC.
- `[TCP] falhou → 192.168.1.1:80` → o socket foi por outra NIC.
- `[HTTP GET] connect falhou: WinError 10061` → idem.
- Porém `[ARP] reply recebido de 192.168.1.1` → **a NIC está viva**
  no nível 2 e **recebeu pacote de volta**.

### Solução: `--raw-only`

O programa detecta automaticamente a ausência de IPv4 e liga **raw-only**,
no qual todos os pacotes saem via `scapy.sendp(iface=...)` presos à
interface escolhida — sem passar pelo roteamento do Windows. Os ciclos
viram:

```
arp  →  raw_icmp  →  raw_tcp_http  →  raw_udp
```

Isso gera tráfego Ethernet legítimo com a L2 correta (`src_mac` da NIC)
independente de haver IP configurado. Para forçar manualmente:

```
python ethkeepalive.py -d 3 --anti-idle --raw-only
```

### Forçar um IP de origem fictício

Alguns switches/routers só processam pacotes com `src IP` válido na
sub-rede. Nesse caso, informe um IP:

```
python ethkeepalive.py -d 3 --anti-idle --raw-only ^
    --src-ip 192.168.1.200 --target 192.168.1.1 ^
    --target-mac aa:bb:cc:dd:ee:ff
```

- `--src-ip` – IPv4 que vai no header dos pacotes raw.
- `--src-mac` – MAC de origem (default: o MAC real da NIC detectado via Scapy).
- `--target-mac` – MAC do próximo salto (default: broadcast). Se você
  souber o MAC do gateway, informar aqui aumenta a chance do ARP e
  demais pacotes serem aceitos pelo switch.

### No seu caso específico (log do console)

A linha `[ARP] reply recebido de 192.168.1.1` confirmou que a `Ethernet
3` **está viva** e tem pelo menos um dispositivo respondendo no outro
lado. O estado `DEGRADED` apareceu só porque os testes L3 (ICMP/TCP
sockets) vão por outra NIC. Rodando novamente com `--raw-only` (ou
simplesmente deixando o auto-detect ativar), o estado fica `HEALTHY`:

```
ethkeepalive.bat -d 3 --anti-idle --lock-nic --raw-only ^
    --target 192.168.1.1
```

Esperado agora:

```
[RAW ICMP] enviado -> 192.168.1.1
[RAW TCP/HTTP] GET enviado -> 192.168.1.1:80
[RAW UDP] enviado -> 192.168.1.1
[ARP] reply recebido de 192.168.1.1
```

Todos como sucesso. O NIC continua recebendo tráfego L2 real.

---

## 10. Troubleshooting — "Nao consegui mapear o adaptador para Scapy"

Esse erro aparece quando o adaptador escolhido na coluna `ID` **não
tem** correspondência direta na lista do Scapy. Causas típicas:

1. **Npcap instalado sem `WinPcap API-compatible Mode`** – reinstale
   marcando essa opção (ver [INSTALL.md](INSTALL.md)).
2. **Adaptador escolhido não é físico** – `WAN Miniport`, `Teredo
   Tunneling`, `Debug Network Adapter` e similares aparecem em
   `Get-NetAdapter` mas o Npcap/Scapy não enxerga. Escolha o adaptador
   `Realtek`/`Intel`/`USB` com MAC preenchido na listagem.
3. **MAC vazio na listagem** – a NIC está no sistema mas sem endereço
   ativo (driver em erro, porta de uma placa dual-port sem cabo). O
   programa agora cai no fallback por GUID/ifIndex; se mesmo assim
   falhar, veja o passo 4.

### Debug passo a passo

a. Rode `python ethkeepalive.py --list-scapy` para ver **exatamente**
   quais interfaces o Scapy enumera:
   ```
   [1] key='\Device\NPF_{XXXX-...-YYYY}'
       network_name='Ethernet'
       description='Realtek PCIe GbE Family Controller'
       mac='a0:ad:9f:13:e4:30'  index=2  guid='xxxx-...-yyyy'
   ```
b. Compare com `--listar` (visão do Windows).
c. Se a NIC está **no `--listar` mas não no `--list-scapy`**:
   - O driver não exporta via Npcap → reinstale Npcap em
     `WinPcap API-compatible Mode`.
   - Ou essa NIC é virtual/driver custom (`#2` de placa dual-port sem
     link) – escolha a outra porta.
d. Se a NIC está **nas duas listagens mas o programa ainda não
   mapeia**:
   - Ao falhar, o programa imprime automaticamente o diagnóstico
     `Scapy x Windows` lado a lado e tenta ler o `InterfaceGuid`.
   - Procure linhas `[resolver]` no console – elas mostram a tentativa
     de match MAC → GUID → ifIndex → nome → descrição.

> No seu caso específico (`Ethernet 3`, `Realtek PCIe GbE Family
> Controller #2` com MAC vazio e `0 bps`): essa é a **segunda porta**
> de uma placa dual-port sem cabo conectado. O Windows mostra a NIC,
> mas o Scapy só vê quem tem um link ativo visível ao driver NDIS.
> Use `-d` apontando para o ID **com MAC preenchido** (no exemplo,
> ID 14 — `Ethernet`, `a0:ad:9f:13:e4:30`, 100 Mbps). Se precisar
> manter especificamente a porta `#2`, conecte um cabo nela primeiro
> (mesmo que seja em um switch).

---

## 11. Burst e perfil `--fast` — tráfego mais denso

Para fazer o padrão parecer uma sessão ativa de verdade (não um "ping
a cada 2s"), use:

```bat
ethkeepalive.bat -d 3 --anti-idle --lock-nic --raw-only ^
    --target 192.168.1.1 --fast
```

O `--fast` é um atalho equivalente a:

```
--interval 0.5 --min-interval 0.5 --jitter 0.15 --burst 3 --keepalive-mode aggressive
```

**O que muda:**

| Opção            | Default         | Com `--fast`     | Efeito                          |
|------------------|-----------------|------------------|----------------------------------|
| `--interval`     | 2.0 s           | 0.5 s            | Ciclos mais curtos               |
| `--jitter`       | 0.3             | 0.15             | Timing menos "metronômico"       |
| `--burst`        | 1               | 3                | 3 pacotes por operação do ciclo  |
| `--keepalive-mode` | basic/adaptive| aggressive       | Acelera se detectar silêncio     |

Ou controle fino:

```bat
python ethkeepalive.py -d 3 --anti-idle --raw-only ^
    --interval 0.8 --jitter 0.2 --burst 5
```

### Como o burst se comporta

Dentro de uma operação (ex.: `raw_tcp_http`), o programa envia **N
pacotes** com 30-120 ms de pausa aleatória entre eles — simulando um
handshake TCP + request + ACK + close. Em seguida respeita o
`--interval` + jitter normal antes da próxima operação do ciclo.

Burst **não** se aplica a sockets Windows (`tcp`, `http_get`,
`http_head`, `http_post`) — esses são mais pesados; a lib limita a 1
por ciclo mesmo que o usuário passe `--burst 10`.

### Limites de segurança preservados

- `SAFETY_MIN_INTERVAL = 0.5 s` (piso absoluto, mesmo com `--fast`).
- `--burst` limitado a 1-20.
- Nenhum flood: o burst termina, respira, e só então começa a próxima
  operação.

---

## 12. Encerramento limpo

- `Ctrl+C` sinaliza o `STOP_EVENT`, para as threads e:
  - Fecha sockets (short e keep-alive).
  - Restaura `AllowComputerToTurnOffDevice` ao valor original (se
    `--lock-nic`).
  - Imprime o resumo estatístico.
- Fechar a janela do console **à força** (clicando no `X`) pula o
  cleanup — prefira sempre `Ctrl+C`.
