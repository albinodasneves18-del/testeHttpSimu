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
```

### Opções (argparse)

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
 ├── listar_dispositivos()      -> PowerShell (Get-NetAdapter -IncludeHidden)
 ├── escolher_dispositivo()     -> interativo ou -d/-i
 ├── resolver_scapy_iface()     -> casa Windows name <-> \Device\NPF_{GUID}
 ├── thread servidor_http_fake  -> socket puro, 200 OK + JSON
 ├── thread watchdog_interface  -> Get-NetAdapter polling
 └── thread gerar_trafego       -> sendp() em loop (http/arp/dhcp/mixed)
```

Todas as threads são `daemon` e observam o `STOP_EVENT`. `Ctrl+C` sinaliza
o evento, as threads saem e o resumo é impresso.

---

## Licença / autoria

Script auxiliar para administração local de rede. Use apenas em
máquinas e redes de sua propriedade.
