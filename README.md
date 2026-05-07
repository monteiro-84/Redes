# RC-TP2 — Packet Sniffer e Analisador de Tráfego

Trabalho Prático N.º 2 — Redes de Computadores 2025/2026  
Grupo PL91 — Gonçalo Monteiro (a110727), Afonso Barbosa (a111074), José Gomes (a110367)

---

## Dependências

O sniffer foi desenvolvido em **Python 3** e requer a biblioteca [Scapy](https://scapy.net/).

### Instalação

```bash
pip install scapy
```

> **Nota:** Em sistemas Linux pode ser necessário usar `pip3` em vez de `pip`.

---

## Execução

A ferramenta pode ser executada de duas formas: **modo interativo** (sem argumentos) ou **modo linha de comandos**.

> **Importante:** A captura de pacotes numa interface real requer permissões de administrador/root.

```bash
# Linux / macOS
sudo python3 sniffer.py

# Windows (terminal como Administrador)
python sniffer.py
```

---

## Modo Interativo

Ao executar o sniffer sem argumentos, é apresentado um menu passo a passo que guia o utilizador pela configuração completa: interface, protocolo, número de pacotes, filtros opcionais e ficheiros de log.

```bash
sudo python3 sniffer.py
```

---

## Modo Linha de Comandos

### Selecionar a interface de rede

```bash
# Listar todas as interfaces disponíveis
sudo python3 sniffer.py --list-ifaces

# Capturar na interface eth0
sudo python3 sniffer.py -i eth0

# Capturar na interface Wi-Fi
sudo python3 sniffer.py -i wlan0
```

### Limitar o número de pacotes

```bash
# Capturar 50 pacotes e parar
sudo python3 sniffer.py -i eth0 -n 50

# Captura contínua (parar com Ctrl+C)
sudo python3 sniffer.py -i eth0 -n 0
```

### Filtros de captura

#### Por protocolo (`-f`)

Valores aceites: `ARP`, `ICMP`, `ICMPv6`, `DNS`, `DHCP`, `HTTP`, `TCP`, `UDP`, `802.11`

```bash
sudo python3 sniffer.py -i eth0 -f ICMP
sudo python3 sniffer.py -i eth0 -f DNS
sudo python3 sniffer.py -i eth0 -f HTTP
```

#### Por endereço IP (`--ip`)

```bash
sudo python3 sniffer.py -i eth0 --ip 192.168.1.1
```

#### Por endereço MAC (`--mac`)

```bash
sudo python3 sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```

#### Por expressão BPF (`--bpf`)

O filtro BPF é aplicado ao nível do kernel (mais eficiente). Exemplos:

```bash
sudo python3 sniffer.py -i eth0 --bpf "tcp port 80"
sudo python3 sniffer.py -i eth0 --bpf "udp port 53"
sudo python3 sniffer.py -i eth0 --bpf "host 192.168.1.1"
sudo python3 sniffer.py -i eth0 --bpf "udp port 67 or udp port 68"
```

### Saída na consola

```bash
# Modo live ativado (comportamento por omissão)
sudo python3 sniffer.py -i eth0 --live

# Desativar saída na consola (útil quando só se quer o log)
sudo python3 sniffer.py -i eth0 --no-live
```

### Estatísticas automáticas

```bash
# Mostrar estatísticas a cada 10 segundos
sudo python3 sniffer.py -i eth0 --stats-interval 10
```

No final da captura (ou em `Ctrl+C`) é também impressa uma **tabela de hierarquia de protocolos** com a distribuição dos pacotes pelas várias camadas (Frame → Ethernet → IPv4/IPv6 → TCP/UDP → HTTP/HTTPS/DNS/DHCP, etc.), com percentagem de pacotes e bytes em cada camada.

### Logging e persistência

Os três formatos podem estar ativos simultaneamente.

```bash
# Guardar em TXT
sudo python3 sniffer.py -i eth0 --log-txt captura.txt

# Guardar em CSV (compatível com Excel / pandas)
sudo python3 sniffer.py -i eth0 --log-csv captura.csv

# Guardar em JSON Lines (processamento programático)
sudo python3 sniffer.py -i eth0 --log-json captura.json

# Guardar nos três formatos ao mesmo tempo
sudo python3 sniffer.py -i eth0 --log-txt cap.txt --log-csv cap.csv --log-json cap.json
```

---

## Referência rápida de parâmetros

| Parâmetro | Exemplo | Descrição |
|---|---|---|
| `-i`, `--iface` | `-i eth0` | Interface de rede a escutar |
| `-n`, `--count` | `-n 100` | Nº de pacotes (0 = infinito) |
| `-f`, `--proto` | `-f ICMP` | Filtro por protocolo |
| `--ip` | `--ip 10.0.0.1` | Filtro por endereço IP |
| `--mac` | `--mac aa:bb:cc:dd:ee:ff` | Filtro por endereço MAC |
| `--bpf` | `--bpf "tcp port 80"` | Filtro BPF (nível kernel) |
| `--live` / `--no-live` | `--no-live` | Ativar/desativar saída na consola |
| `--log-txt` | `--log-txt cap.txt` | Log em ficheiro TXT |
| `--log-csv` | `--log-csv cap.csv` | Log em ficheiro CSV |
| `--log-json` | `--log-json cap.json` | Log em ficheiro JSON |
| `--stats-interval` | `--stats-interval 5` | Estatísticas a cada N segundos |
| `--list-ifaces` | `--list-ifaces` | Listar interfaces disponíveis |

---

## Como correr no emulador CORE

1. Abrir o CORE e carregar (ou criar) a topologia com os nós PC1, PC2 e sniffer ligados a um switch.
2. Clicar com o botão direito no nó **sniffer** → **Terminal**.
3. Copiar o ficheiro `sniffer.py` para o nó (ou usar um serviço de ficheiros partilhados do CORE).
4. No terminal do nó sniffer, executar:

```bash
# Ativar modo promíscuo para capturar tráfego entre outros nós
ip link set eth0 promisc on

# Iniciar o sniffer (no CORE não é necessário sudo)
python3 sniffer.py -i eth0
```

5. Nos terminais do PC1 / PC2, gerar tráfego:

```bash
# ICMP
ping 10.0.0.21

# ARP (limpar cache primeiro)
ip neigh flush all && ping 10.0.0.21 -c 1

# HTTP (no PC2 iniciar servidor; no PC1 ou sniffer fazer pedido)
python3 -m http.server 80        # PC2
curl http://10.0.0.21/           # PC1 ou sniffer
```

---

## Como correr no PC real

1. Verificar a interface ativa:

```bash
# Linux
ip link show

# macOS
ifconfig
```

2. Executar o sniffer com permissões de root:

```bash
# Exemplo Wi-Fi no Linux
sudo python3 sniffer.py -i wlp0s20f3

# Exemplo Ethernet no macOS
sudo python3 sniffer.py -i en0
```

3. Para capturar tráfego específico, combinar filtros:

```bash
# Apenas DNS
sudo python3 sniffer.py -i wlp0s20f3 --bpf "udp port 53" --log-csv dns.csv

# Renovar endereço DHCP (noutro terminal) e capturar o processo DORA
sudo python3 sniffer.py -i wlp0s20f3 --bpf "udp port 67 or udp port 68"
# noutro terminal:
sudo dhclient -r wlp0s20f3 && sudo dhclient wlp0s20f3
```

> **Nota:** A captura de frames IEEE 802.11 requer que a interface esteja em **modo monitor**, o que implica configuração adicional do sistema operativo e nem sempre é possível sem hardware compatível.

---

## Protocolos suportados

| Protocolo | Identificação | Informação extraída |
|---|---|---|
| ARP | Camada Ethernet | Request/Reply, IP origem/destino, MAC |
| ICMP | IPv4 | Echo Request/Reply, Dest Unreachable, Time Exceeded |
| ICMPv6 | IPv6 | Echo Request/Reply, id, seq |
| DNS | UDP porta 53 | Query/Response, nome pedido, endereços devolvidos |
| DHCP | UDP portas 67/68 | Tipo (DORA), IP atribuído, hostname |
| HTTP | TCP porta 80/8080 | Método, host, path (pedidos); código de estado (respostas) |
| HTTPS | TCP porta 443 | Distinguido na tabela de hierarquia (payload cifrado) |
| TCP | IPv4/IPv6 | Flags (SYN, ACK, FIN, RST, PSH, URG), seq, ack |
| UDP | IPv4/IPv6 | Portas origem/destino, tamanho |
| IPv6 | Ethernet | Endereços, next-header |
| IEEE 802.11 | Modo monitor | Beacon (SSID), Probe Request |

---

## Tabela de hierarquia de protocolos

No final de cada captura (ou ao premir `Ctrl+C`), o sniffer imprime uma tabela com a distribuição dos pacotes pelas camadas do modelo, semelhante à *Protocol Hierarchy Statistics* do Wireshark. Cada linha mostra a percentagem de pacotes, número absoluto de pacotes, percentagem de bytes e número de bytes em cada camada:

```
Hierarquia de Protocolos
  Protocolo             % Pacotes   Pacotes  % Bytes        Bytes
  ─────────────────────────────────────────────────────────────────
  Frame                    100.0%       150   100.0%       18,420
    Ethernet               100.0%       150   100.0%       18,420
      IPv4                  92.0%       138    93.5%       17,222
        TCP                 60.0%        90    72.0%       13,262
          HTTPS             45.0%        68    65.0%       11,973
        UDP                 28.0%        42    18.0%        3,316
          DNS               25.0%        38    16.0%        2,947
      ARP                    8.0%        12     6.5%        1,198
```

A indentação reflete o encapsulamento: cada camada inferior está contida na superior. Permite identificar de imediato a composição do tráfego capturado.
