# INSTALL — passo a passo (Windows 11 x64)

Este guia instala tudo que o **EthKeepAlive** precisa em uma máquina
Windows 11 x64. Há duas trilhas: a **automática** (um script `.bat` cuida
de tudo) e a **manual** (você faz passo a passo).

---

## Pré-requisitos

- Windows 10/11 x64.
- Conta de usuário com permissão de Administrador local.
- Conexão com a Internet para baixar os instaladores.
- Aproximadamente **120 MB** livres (Python ~30 MB + Npcap ~1 MB +
  dependências).

---

## 🅰️ Trilha automática — `install.bat`

1. Copie o conteúdo deste projeto para uma pasta de sua escolha, por
   exemplo `C:\tools\ethkeepalive\`. A pasta deve conter pelo menos:
   ```
   ethkeepalive.py
   ethkeepalive.bat
   ethkeepalive-listar.bat
   install.bat
   README.md
   INSTALL.md
   EXECUCAO.md
   ```

2. Clique com o **botão direito** em `install.bat` → **Executar como
   administrador** (se você não clicar, o próprio script detecta e pede
   elevação via UAC).

3. Acompanhe o console. Ele vai, nesta ordem:

   | Passo | Ação                                                            |
   |:-----:|-----------------------------------------------------------------|
   | 1/4   | Baixa `python-3.12.5-amd64.exe` em `.\deps\` e instala em modo silencioso (`InstallAllUsers=1`, `PrependPath=1`). Se já houver Python no `PATH`, pula. |
   | 2/4   | Atualiza o `pip` e roda `pip install scapy`.                    |
   | 3/4   | Baixa `npcap-1.80.exe` em `.\deps\` e abre o instalador. **Marque** `Install Npcap in WinPcap API-compatible Mode` e clique `I Agree → Install → Finish`. |
   | 4/4   | Faz um smoke-test (`import scapy`, `python ethkeepalive.py --listar`). |

4. Ao final, o console mostrará algo como:
   ```
   scapy OK.
   ethkeepalive.py --listar: OK
   Instalacao concluida.
   ```

5. Pronto. Siga para [EXECUCAO.md](EXECUCAO.md).

> **Se `install.bat` falhar em algum passo**, ele mostra o motivo e qual
> arquivo baixar manualmente. Os links oficiais estão fixados no script.

---

## 🅱️ Trilha manual — passo a passo

### Passo 1 — Instalar Python 3.12

1. Abra <https://www.python.org/downloads/windows/>.
2. Baixe **Windows installer (64-bit)** da versão 3.12.x.
3. Execute o instalador.
4. **MARQUE** a caixa `Add python.exe to PATH` **antes** de clicar em
   `Install Now`.
5. Confirme no `cmd`:
   ```
   python --version
   pip --version
   ```

### Passo 2 — Instalar Scapy

1. Abra `cmd` como **Administrador**.
2. Rode:
   ```
   pip install scapy
   ```
3. Confirme:
   ```
   python -c "import scapy; print(scapy.__version__)"
   ```

### Passo 3 — Instalar Npcap (**crítico**)

1. Baixe em <https://npcap.com/#download> a versão mais recente (ex.: `npcap-1.80.exe`).
2. Execute o instalador.
3. Na tela de opções, **MARQUE**:
   - ☒ **Install Npcap in WinPcap API-compatible Mode** (obrigatório — sem isso o Scapy não enxerga as interfaces)
   - ☒ `Support raw 802.11 traffic (and monitor mode) for wireless adapters` (opcional)
   - ☐ `Install Npcap in loopback mode` (opcional)
4. Reinicie o terminal (ou faça logoff/logon) para o serviço aparecer.

### Passo 4 — Baixar os arquivos do projeto

Coloque numa pasta (ex.: `C:\tools\ethkeepalive\`):

```
ethkeepalive.py
ethkeepalive.bat
ethkeepalive-listar.bat
install.bat        (opcional, mas útil para re-instalar)
README.md
INSTALL.md
EXECUCAO.md
```

### Passo 5 — Smoke-test

Abra um `cmd` **como Administrador** e rode:

```
cd C:\tools\ethkeepalive
python ethkeepalive.py --listar
```

Você deve ver uma tabela listando todos os adaptadores de rede.

Em seguida, teste o diagnóstico sem gerar tráfego:

```
python ethkeepalive.py -d 1 --diagnostic
```

Esperado: um relatório `[OK]/[WARN]/[FAIL]/[SKIP]` para Scapy, Npcap,
Interface, Link, IPv4, MAC, ifIndex, Connectivity, Power Management e
Can send.

---

## Troubleshooting rápido

| Sintoma                                            | Causa provável                              | Correção                                                                 |
|----------------------------------------------------|---------------------------------------------|--------------------------------------------------------------------------|
| `python` não é reconhecido                         | PATH não foi marcado                        | Reinstale o Python marcando `Add python.exe to PATH`.                    |
| `No libpcap provider available`                    | Npcap faltando ou em modo errado            | Reinstale o Npcap marcando `WinPcap API-compatible Mode`.                |
| `PermissionError` ao enviar pacote                 | Terminal não é admin                        | Feche e reabra como Administrador.                                       |
| `Nao consegui mapear o adaptador para Scapy`       | GUID do adaptador mudou                     | Rode `--listar` de novo; use `-i "nome exato"`.                          |
| `pip install scapy` fica preso em "Collecting"     | Rede corporativa com proxy                  | Rode `pip install --proxy http://usuario:senha@proxy:porta scapy`.       |
| `install.bat` falha ao baixar Python ou Npcap      | Firewall/proxy bloqueando                   | Baixe manualmente e coloque em `.\deps\`. O script detecta e segue.      |

---

## Desinstalar

```
pip uninstall scapy
```

E, se quiser remover Python/Npcap, use `Painel de Controle → Programas
e Recursos`. Os arquivos deste projeto podem ser apagados simplesmente
deletando a pasta.
