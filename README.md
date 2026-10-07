# EthKeepAlive

Mantém um adaptador Ethernet do Windows 11 ativo gerando tráfego sintético
(Ether/IP/TCP com payload HTTP, ARP e DHCP) em uma interface escolhida pelo
usuário. Inclui servidor HTTP fake embutido, watchdog para reconexão e
suporte a múltiplos protocolos.

> **Aviso:** o script gera tráfego para evitar que o adaptador fique
> ocioso, mas **não impede** o Windows de desativar a placa por
> políticas de economia de energia. Para garantir, desmarque
> *"Permitir que o computador desligue este dispositivo"* nas
> propriedades do adaptador (Gerenciador de Dispositivos).

---

## Instalação

### 1. Pré-requisitos

- Windows 11 (ou Windows 10 recente).
- **Python 3.10+** (recomenda-se 3.11 ou 3.12). Baixe em
  <https://www.python.org/downloads/windows/> e marque *"Add Python to PATH"*.
- **Npcap** em modo *WinPcap API-compatible*:
  1. Baixe o instalador em <https://npcap.com/#download>.
  2. Durante a instalação, **marque** as duas opções:
     - `Install Npcap in WinPcap API-compatible Mode`
     - `Support raw 802.11 traffic (and monitor mode) for wireless adapters` (opcional)
  3. Reinicie se solicitado.

### 2. Dependência Python

Abra o `cmd` ou `PowerShell` **como Administrador** e rode:

```powershell
pip install scapy
```

Nenhum outro pacote é exigido — apenas a biblioteca padrão.

### 3. Baixar o script

Salve `ethkeepalive.py` em qualquer pasta, por exemplo `C:\tools\ethkeepalive\`.

### 4. Rodar como Administrador

Envio raw de pacotes (camada 2) exige privilégios elevados. Clique com o
botão direito no `cmd` / `PowerShell` e escolha
**"Executar como administrador"**, então navegue até a pasta do script.

### 4b. Atalho via `ethkeepalive.bat`

Para quem preferir **clique duplo**, use o arquivo `ethkeepalive.bat`
(incluído no projeto). Ele:

1. Pede elevação UAC automaticamente se não estiver como Administrador.
2. Verifica se `python` está no PATH.
3. Instala `scapy` se faltar.
4. Avisa se o Npcap aparentemente não está presente.
5. Executa o programa em uma janela de console e **pausa** no final
   para você poder ler a saída.

Sem argumentos, executa com os padrões recomendados:

```bat
python ethkeepalive.py --anti-idle --lock-nic
```

Com argumentos, repassa tudo:

```bat
ethkeepalive.bat --listar
ethkeepalive.bat -d 2 --proto mixed
ethkeepalive.bat -d 2 --keepalive-mode aggressive --lock-nic
```

Também há `ethkeepalive-listar.bat` para listar os adaptadores sem
precisar de elevação.

---

## Uso rápido

```powershell
# Listar todos os adaptadores detectados
python ethkeepalive.py --listar

# Modo interativo (pergunta o ID na tela)
python ethkeepalive.py

# Escolher pelo ID da listagem, a cada 1 segundo, para 192.168.1.100
python ethkeepalive.py -d 2 -t 192.168.1.100 -n 1

# Escolher pelo nome da interface do Windows e alternar protocolos
python ethkeepalive.py -i "Ethernet 2" --proto mixed

# Rodar em background com log em arquivo e sem servidor HTTP
python ethkeepalive.py -d 2 --sem-http --quiet --log keepalive.log

# Reproduzir um pcap em loop pela interface escolhida
python ethkeepalive.py -d 2 --pcap captura.pcap

# Verificar quais placas podem ser desligadas pelo Windows
python ethkeepalive.py --check-power

# AdaptiveKeepAlive - modo recomendado (anti-idle)
python ethkeepalive.py -d 2 --anti-idle

# AdaptiveKeepAlive mais insistente, com jitter e porta HTTP alvo
python ethkeepalive.py -d 2 --keepalive-mode aggressive \
    --target 192.168.1.1 --target-port 80 --jitter 0.5 \
    --min-interval 1 --max-interval 60

# Rodar apenas o diagnostico (nao envia trafego continuo)
python ethkeepalive.py -d 2 --diagnostic
```

### Opções (argparse)

**Modo clássico (`--keepalive-mode basic`, padrão):**

| Opção                  | Descrição                                                         |
|------------------------|-------------------------------------------------------------------|
| `-l`, `--listar`       | Lista dispositivos e sai                                          |
| `-d`, `--device <ID>`  | ID do dispositivo (ver `--listar`)                                |
| `-i`, `--interface <nome>` | Nome ou descrição parcial da interface                        |
| `-t`, `--target <IP>`  | IP de destino dos pacotes (padrão `192.168.1.1`)                  |
| `-p`, `--port <porta>` | Porta HTTP destino e do servidor fake (padrão `80`)               |
| `-n`, `--interval <s>` | Intervalo entre pacotes em segundos (padrão `2.0`)                |
| `-m`, `--mac <MAC>`    | MAC de destino (padrão `ff:ff:ff:ff:ff:ff`)                       |
| `--proto <tipo>`       | `http` \| `arp` \| `dhcp` \| `mixed` (padrão `http`)              |
| `--sem-http`           | Não iniciar servidor HTTP fake                                    |
| `--quiet`              | Modo silencioso (grava só no arquivo de log)                      |
| `--log <arquivo>`      | Arquivo de log opcional                                           |
| `--pcap <arquivo>`     | Reproduz um `.pcap` em loop                                       |
| `--check-power`        | Mostra políticas de energia dos adaptadores e sai                 |
| `-h`, `--help`         | Ajuda                                                             |
| `--version`            | Versão                                                            |

**AdaptiveKeepAlive (camada de resiliência):**

| Opção                      | Descrição                                                       |
|----------------------------|-----------------------------------------------------------------|
| `--keepalive-mode <m>`     | `basic` (padrão) \| `adaptive` \| `aggressive`                  |
| `--anti-idle`              | Atalho: ativa `--keepalive-mode adaptive` + diagnóstico         |
| `--diagnostic`             | Executa o diagnóstico completo e sai                            |
| `--jitter <s>`             | Variação aleatória do intervalo (padrão `0.3`, máx. `5`)        |
| `--min-interval <s>`       | Intervalo mínimo entre testes (padrão `1.0`, piso `0.5`)        |
| `--max-interval <s>`       | Intervalo máximo (padrão `30`, teto `300`)                      |
| `--target-port <porta>`    | Porta TCP de destino para os testes (padrão `80`)               |
| `--http-host <host>`       | Header `Host` das requisições HTTP (padrão: `--target`)         |
| `--http-url <path>`        | Caminho usado nos HTTP GET/HEAD/POST (padrão `/`)               |
| `--tcp-mode <modo>`        | `short` (padrão) \| `keep-alive` (reaproveita um socket)        |
| `--lock-nic`               | Tenta impedir Windows de desativar/desligar a NIC enquanto roda |

Modos:

- **basic** – mantém o comportamento original (loop simples sobre `--proto`).
- **adaptive** – alterna automaticamente entre ICMP, TCP connect, HTTP
  GET/HEAD/POST e ARP, com testes de conectividade reais, backoff após
  falhas e jitter controlado.
- **aggressive** – como adaptive, mas reduz temporariamente o intervalo
  (sempre acima do piso de segurança) quando detecta período prolongado
  sem sucesso.

> O programa **não altera** as configurações de energia da NIC. Se o
> Windows estiver configurado para desligar o adaptador por economia de
> energia, o diagnóstico avisa — a correção é manual (Gerenciador de
> Dispositivos → aba *Gerenciamento de energia*).

---

## Tabela de recursos implementados

| Recurso                                                              | Status |
|----------------------------------------------------------------------|:------:|
| Listagem completa via `Get-NetAdapter` (visíveis + ocultos)          |  OK    |
| Exibição em tabela: ID, Status, Nome, Descrição, MAC, LinkSpeed, ifIndex | OK |
| Seleção por `-d`, `-i` ou modo interativo                            |  OK    |
| Resolução automática do nome do Scapy (`\Device\NPF_{GUID}`)         |  OK    |
| Pacotes Ether/IP/TCP com payload HTTP (GET e POST, headers realistas) | OK    |
| Loop infinito com intervalo configurável e contador de sequência     |  OK    |
| MAC de destino configurável (padrão broadcast)                       |  OK    |
| Servidor HTTP fake embutido (socket puro, sem Flask)                 |  OK    |
| Resposta `200 OK` + JSON com timestamp ISO                           |  OK    |
| Protocolos: `http`, `arp`, `dhcp`, `mixed`                           |  OK    |
| Watchdog periódico de status da interface                            |  OK    |
| Log em arquivo com timestamp e modo silencioso                       |  OK    |
| Encerramento limpo em `Ctrl+C` / SIGTERM                             |  OK    |
| Reprodução de `.pcap` em loop                                        |  OK    |
| Detecção de economia de energia (`--check-power`)                    |  OK    |
| Resumo estatístico ao encerrar                                       |  OK    |
| Checagem de privilégio de Administrador                              |  OK    |
| **AdaptiveKeepAlive**: ciclos ICMP → TCP → HTTP GET/HEAD/POST → ARP  |  OK    |
| Modos `basic`, `adaptive`, `aggressive` (`--keepalive-mode`)         |  OK    |
| Jitter + `--min-interval` / `--max-interval` com piso de segurança   |  OK    |
| Máquina de estados `STARTING → HEALTHY → DEGRADED → DISCONNECTED → RECOVERING` | OK |
| Watchdog acoplado que pausa envios enquanto a NIC está Down          |  OK    |
| Bind TCP/HTTP no IPv4 da NIC (interface source selection)            |  OK    |
| `--tcp-mode short` / `keep-alive` (socket reaproveitado)             |  OK    |
| Testes de conectividade reais (`PACKET_SENT` ≠ `HTTP_SUCCESS`)       |  OK    |
| Backoff exponencial moderado após 3 falhas consecutivas              |  OK    |
| `--diagnostic` com relatório `[OK]/[WARN]/[FAIL]/[SKIP]`             |  OK    |
| `--anti-idle` como atalho de adaptativo + diagnóstico                |  OK    |
| Aviso claro sobre gerenciamento de energia (sem alterar automaticamente) | OK |
| Limite rígido de 1 conexão TCP simultânea (sem flood)                |  OK    |
| **`--lock-nic`**: desativa `AllowComputerToTurnOffDevice` + `Enable-NetAdapter` + guardião | OK |
| Snapshot do estado original e restauração automática ao sair         |  OK    |
| `ethkeepalive.bat` com auto-elevação UAC, pip-install e checagem Npcap |  OK    |
| `ethkeepalive-listar.bat` (lista adaptadores sem exigir elevação)    |  OK    |

---

## Solução de problemas

### "No libpcap provider available" ou "No such device"

- O **Npcap** não está instalado ou foi instalado **sem** o modo
  *WinPcap API-compatible*. Reinstale e marque a opção corretamente.
- Reinicie o terminal após instalar o Npcap.

### "PermissionError" ou nada é enviado

- Você não está rodando como Administrador. Feche o terminal e
  reabra com **"Executar como administrador"**.

### "ID X não encontrado" ou interface não aparece

- Rode `python ethkeepalive.py --listar` para confirmar a numeração.
- Se um adaptador USB foi conectado/desconectado, a numeração pode mudar
  entre execuções. Prefira `-i "Ethernet 2"` ou use a descrição.

### "Não consegui mapear o adaptador para uma interface do Scapy"

- Isso costuma ser Npcap em modo errado. Verifique:
  ```powershell
  Get-Service npcap
  Get-Service npf
  ```
- Reinstale Npcap marcando *WinPcap API-compatible Mode*.

### A placa continua caindo

- Isso é política de energia do Windows, não falta de tráfego.
- Rode `python ethkeepalive.py --check-power` para localizar placas
  com `AllowComputerToTurnOffDevice = Enabled`.
- No **Gerenciador de Dispositivos**:
  1. Expanda **Adaptadores de rede**.
  2. Clique com o botão direito no adaptador → **Propriedades**.
  3. Aba **Gerenciamento de energia** → desmarque
     *"Permitir que o computador desligue este dispositivo para economizar energia"*.
  4. Clique **OK**.
- Como alternativa via PowerShell (Administrador):
  ```powershell
  Set-NetAdapterPowerManagement -Name "Ethernet 2" -AllowComputerToTurnOffDevice Disabled
  ```

### O servidor HTTP fake não sobe (porta 80 ocupada)

- Alguma coisa já está escutando na porta 80 (IIS, Skype antigo, etc.).
- Passe `-p 8080` ou use `--sem-http`.

### "Scapy não está disponível"

- Rode `pip install scapy` (de preferência no mesmo Python onde roda o
  script). Teste com `python -c "import scapy; print(scapy.__version__)"`.

---

## Arquitetura (resumida)

```
main()
 ├── listar_dispositivos()         -> PowerShell (Get-NetAdapter -IncludeHidden)
 ├── escolher_dispositivo()        -> interativo ou -d/-i
 ├── resolver_scapy_iface()        -> casa Windows name <-> \Device\NPF_{GUID}
 ├── _guess_local_ip/_ipv6()       -> IPv4/IPv6 do adaptador (bind source)
 ├── executar_diagnostico()        -> relatório [OK]/[WARN]/[FAIL]
 ├── thread servidor_http_fake     -> socket puro, 200 OK + JSON
 ├── thread watchdog_interface(_adaptive) -> Get-NetAdapter polling
 └── MODO:
      ├── basic:   gerar_trafego()        -> sendp() em loop (http/arp/dhcp/mixed)
      └── adaptive/aggressive:
            AdaptiveKeepAlive.run()
             ├── ciclos: ICMP -> TCP -> HTTP GET -> HTTP HEAD -> HTTP POST -> ARP
             ├── bind TCP/HTTP no IPv4 da NIC
             ├── jitter + backoff exponencial (dentro dos limites)
             ├── máquina de estados STARTING→HEALTHY→DEGRADED→DISCONNECTED→RECOVERING
             └── telemetria PACKET_SENT / ICMP_SUCCESS / TCP_CONNECTED / HTTP_SUCCESS
```

Todas as threads são `daemon` e observam o `STOP_EVENT`. `Ctrl+C` sinaliza
o evento, as threads saem e o resumo é impresso.

---

## AdaptiveKeepAlive — regra fundamental

O `EthKeepAlive` trata **"manter atividade"** e **"impedir que o Windows
desligue a NIC por economia de energia"** como problemas diferentes:

- O **AdaptiveKeepAlive** gera tráfego legítimo e variado, verifica
  conectividade real (ICMP/TCP/HTTP), monitora o estado da NIC via
  `Get-NetAdapter` / `Get-NetAdapterStatistics` e recupera-se automaticamente
  quando o link volta.
- **Não** há garantia de que gerar tráfego impeça o Windows de desativar
  o adaptador por política de energia. Se o diagnóstico detectar
  `AllowComputerToTurnOffDevice = Enabled`, o programa avisa claramente
  e orienta a desmarcar manualmente, mas nunca altera a configuração
  por conta própria.

### Distinção entre estados detectados

| Situação                                 | Como o programa percebe                                   |
|------------------------------------------|-----------------------------------------------------------|
| Interface **sem tráfego**                | `last_activity` cresce → aumenta cadência (aggressive)    |
| Interface **sem conectividade**          | Testes ICMP/TCP/HTTP falham → estado `DEGRADED` + backoff |
| Interface **administrativamente Disabled** | `Get-NetAdapter.Status = Disabled` → pausa envios        |
| Interface **afetada por energia**        | `--check-power` / diagnóstico mostra `[WARN]`             |
| **Link físico caiu**                     | `Status = Down/Disconnected` → `DISCONNECTED` → `RECOVERING` |

### Limites de segurança (fixos no código)

- `SAFETY_MIN_INTERVAL = 0.5 s` — nunca envia mais rápido que isso.
- `SAFETY_MAX_INTERVAL = 300 s` — teto absoluto do backoff.
- `SAFETY_MAX_PAYLOAD  = 2048 B` — payload HTTP é truncado.
- `SAFETY_MAX_CONCURRENT = 1`   — no máximo uma conexão TCP ao mesmo tempo.
- Sem flood, sem broadcast contínuo, todas as threads têm `sleep`.

### `--lock-nic` — impedir desativação da NIC enquanto roda

Ao passar `--lock-nic`, o programa:

1. Lê o estado atual via `Get-NetAdapterPowerManagement` e `Get-NetAdapter`
   e guarda um **snapshot**.
2. Executa `Set-NetAdapterPowerManagement -AllowComputerToTurnOffDevice
   Disabled -NoRestart` para impedir que o Windows desligue o dispositivo
   para "economizar energia".
3. Se a interface estiver `Disabled`, executa `Enable-NetAdapter -Confirm:$false`.
4. Inicia uma thread guardiã (`nic_guard`) que a cada 10 s re-aplica o
   lock se algo externo tiver desfeito.
5. No encerramento (Ctrl+C, SIGTERM, fim do `main()`), **restaura o
   estado original** salvo no snapshot.

Pré-requisito: `--lock-nic` só funciona em Windows **como Administrador**.
Fora disso, é ignorado com log.

> **Honestidade sobre garantias:** este bloqueio reduz drasticamente a
> chance do Windows desativar a NIC por economia de energia, mas **não
> é absoluto**. GPO corporativas, drivers OEM customizados, Mobility
> Center e políticas agressivas de bateria podem sobrepor
> `Set-NetAdapterPowerManagement`. O programa logga quando detecta
> reversão e tenta reaplicar, mas não há forma documentada de impedir
> 100% o SO. Para hardening máximo, combine com a configuração manual
> em *Gerenciador de Dispositivos → Propriedades da NIC → Gerenciamento
> de energia* desmarcada e, se houver GPO, converse com a TI.

---

## Licença / autoria

Script auxiliar para administração local de rede. Use apenas em
máquinas e redes de sua propriedade.
