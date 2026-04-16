#!/usr/bin/env python3
"""
RC-TP2 Packet Sniffer
Redes de Computadores, Universidade do Minho 2025/2026
"""

import argparse
import csv
import json
import signal
import threading
import sys
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, ARP, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply,
        DNS, DNSQR, DNSRR, DHCP, BOOTP, Ether, Raw,
        get_if_list, conf
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq
except ImportError:
    print("[ERRO] Scapy não está instalado. Corre: pip install scapy")
    sys.exit(1)


# ─────────────────────────────────────────────
# CORES para output na consola
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"


PROTO_COLORS = {
    "ARP":    C.YELLOW,
    "ICMP":   C.CYAN,
    "ICMPv6": C.CYAN,
    "DNS":    C.MAGENTA,
    "DHCP":   C.GREEN,
    "HTTP":   C.BLUE,
    "TCP":    C.WHITE,
    "UDP":    C.GREY,
    "IPv6":   C.GREEN,
    "802.11": C.RED,
    "OTHER":  C.RESET,
}


# ─────────────────────────────────────────────
# Estado global (thread-safe)
# ─────────────────────────────────────────────
_lock = threading.Lock()
packet_counter = 0

stats = {
    "total":      0,
    "by_proto":   defaultdict(int),
    "bytes":      0,
    "start_time": None,
}

# Ficheiros de log
log_txt      = None
log_csv      = None
log_json_path = ""
csv_writer   = None
json_records = []

# Flag de paragem para o loop de estatísticas
_stop_stats = threading.Event()


# ─────────────────────────────────────────────
# Loop periódico de estatísticas
# ─────────────────────────────────────────────
def _stats_loop(interval):
    """Imprime estatísticas de N em N segundos. Para quando _stop_stats é set."""
    while not _stop_stats.wait(timeout=interval):
        _print_stats()


# ─────────────────────────────────────────────
# Identificação e resumo do pacote
# ─────────────────────────────────────────────
def identify_packet(pkt):
    """Retorna (protocolo, src, dst, resumo, mac_src, mac_dst) do pacote."""
    proto   = "OTHER"
    src     = "?"
    dst     = "?"
    summary = ""

    # ── Endereços Ethernet ────────────────────
    if Ether in pkt:
        eth_src = pkt[Ether].src
        eth_dst = pkt[Ether].dst
    else:
        eth_src = eth_dst = "N/A"

    # ── ARP ───────────────────────────────────
    if ARP in pkt:
        proto = "ARP"
        src   = pkt[ARP].psrc
        dst   = pkt[ARP].pdst
        op    = pkt[ARP].op
        if op == 1:
            summary = f"ARP Request: Quem tem {dst}? Diz a {src}"
        elif op == 2:
            summary = f"ARP Reply: {src} está em {eth_src}"
        else:
            summary = f"ARP op={op}"
        return proto, src, dst, summary, eth_src, eth_dst

    # ── DHCP (deve ser verificado antes de DNS, usa UDP 67/68) ───
    # DHCP usa BOOTP por baixo; verificamos antes do DNS genérico
    if DHCP in pkt:
        return _dhcp_info(pkt, src, dst, eth_src, eth_dst)

    # ── IPv6 ──────────────────────────────────
    if IPv6 in pkt and IP not in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        nh  = pkt[IPv6].nh

        if ICMPv6EchoRequest in pkt:
            proto   = "ICMPv6"
            summary = f"ICMPv6 Echo Request id={pkt[ICMPv6EchoRequest].id} seq={pkt[ICMPv6EchoRequest].seq}"
        elif ICMPv6EchoReply in pkt:
            proto   = "ICMPv6"
            summary = f"ICMPv6 Echo Reply id={pkt[ICMPv6EchoReply].id} seq={pkt[ICMPv6EchoReply].seq}"
        elif DNS in pkt:
            return _dns_info(pkt, src, dst, eth_src, eth_dst)
        elif TCP in pkt:
            return _tcp_info(pkt, src, dst, eth_src, eth_dst)
        elif UDP in pkt:
            return _udp_info(pkt, src, dst, eth_src, eth_dst)
        else:
            proto   = "IPv6"
            summary = f"IPv6 next-header={nh}"

        return proto, src, dst, summary, eth_src, eth_dst

    # ── IPv4 ──────────────────────────────────
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # ICMP
        if ICMP in pkt:
            proto = "ICMP"
            t     = pkt[ICMP].type
            code  = pkt[ICMP].code
            if t == 8:
                summary = f"ICMP Echo Request  id={pkt[ICMP].id} seq={pkt[ICMP].seq}"
            elif t == 0:
                summary = f"ICMP Echo Reply    id={pkt[ICMP].id} seq={pkt[ICMP].seq}"
            elif t == 3:
                summary = f"ICMP Dest Unreachable code={code}"
            elif t == 11:
                summary = "ICMP Time Exceeded (TTL=0)"
            else:
                summary = f"ICMP type={t} code={code}"
            return proto, src, dst, summary, eth_src, eth_dst

        # DNS (UDP/TCP porta 53)
        if DNS in pkt:
            return _dns_info(pkt, src, dst, eth_src, eth_dst)

        # HTTP (TCP porta 80/8080)
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport in (80, 8080) or dport in (80, 8080):
                if HTTPRequest in pkt:
                    proto   = "HTTP"
                    method  = pkt[HTTPRequest].Method.decode(errors="replace") if pkt[HTTPRequest].Method else "?"
                    path    = pkt[HTTPRequest].Path.decode(errors="replace")   if pkt[HTTPRequest].Path   else "/"
                    host    = pkt[HTTPRequest].Host.decode(errors="replace")   if pkt[HTTPRequest].Host   else dst
                    summary = f"HTTP {method} {host}{path}"
                    return proto, src, dst, summary, eth_src, eth_dst
                elif HTTPResponse in pkt:
                    proto   = "HTTP"
                    status  = pkt[HTTPResponse].Status_Code.decode(errors="replace")    if pkt[HTTPResponse].Status_Code    else "?"
                    reason  = pkt[HTTPResponse].Reason_Phrase.decode(errors="replace")  if pkt[HTTPResponse].Reason_Phrase  else ""
                    summary = f"HTTP Response {status} {reason}"
                    return proto, src, dst, summary, eth_src, eth_dst

            return _tcp_info(pkt, src, dst, eth_src, eth_dst)

        if UDP in pkt:
            return _udp_info(pkt, src, dst, eth_src, eth_dst)

        proto   = "OTHER"
        summary = f"IPv4 proto={pkt[IP].proto}"
        return proto, src, dst, summary, eth_src, eth_dst

    # ── IEEE 802.11 ───────────────────────────
    if Dot11 in pkt:
        proto = "802.11"
        src   = pkt[Dot11].addr2 or "?"
        dst   = pkt[Dot11].addr1 or "?"
        if Dot11Beacon in pkt:
            ssid    = pkt[Dot11Beacon].network_stats().get("ssid", "?")
            summary = f"802.11 Beacon SSID={ssid}"
        elif Dot11ProbeReq in pkt:
            summary = "802.11 Probe Request"
        else:
            summary = f"802.11 type={pkt[Dot11].type} subtype={pkt[Dot11].subtype}"
        return proto, src, dst, summary, eth_src, eth_dst

    # ── Fallback ──────────────────────────────
    summary = pkt.summary()[:80]
    return "OTHER", "?", "?", summary, eth_src, eth_dst


# ─────────────────────────────────────────────
# Helpers de protocolos
# ─────────────────────────────────────────────
def _tcp_flags(flags):
    names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
             0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    return "|".join(n for b, n in names.items() if int(flags) & b) or str(flags)


def _tcp_info(pkt, src, dst, eth_src, eth_dst):
    tcp      = pkt[TCP]
    sport    = tcp.sport
    dport    = tcp.dport
    flag_str = _tcp_flags(tcp.flags)
    summary  = f"TCP {src}:{sport} → {dst}:{dport} [{flag_str}] seq={tcp.seq} ack={tcp.ack}"
    return "TCP", f"{src}:{sport}", f"{dst}:{dport}", summary, eth_src, eth_dst


def _udp_info(pkt, src, dst, eth_src, eth_dst):
    udp     = pkt[UDP]
    sport   = udp.sport
    dport   = udp.dport
    summary = f"UDP {src}:{sport} → {dst}:{dport} len={udp.len}"
    return "UDP", f"{src}:{sport}", f"{dst}:{dport}", summary, eth_src, eth_dst


def _dns_info(pkt, src, dst, eth_src, eth_dst):
    dns = pkt[DNS]
    if dns.qr == 0:
        qname   = dns.qd.qname.decode(errors="replace") if dns.qd else "?"
        summary = f"DNS Query: {qname}"
    else:
        answers = []
        an = dns.an
        while an:
            if hasattr(an, "rdata"):
                answers.append(str(an.rdata))
            an = an.payload if hasattr(an, "payload") and isinstance(an.payload, DNSRR) else None
        summary = f"DNS Response: {', '.join(answers[:3]) or '(sem resposta)'}"
    return "DNS", src, dst, summary, eth_src, eth_dst


def _dhcp_info(pkt, src, dst, eth_src, eth_dst):
    dhcp_opts = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}
    msg_type  = dhcp_opts.get("message-type", 0)
    types     = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                 5: "ACK",      6: "NAK",   7: "Release", 8: "Inform"}
    t       = types.get(msg_type, f"type={msg_type}")
    summary = f"DHCP {t}"
    if "requested_addr" in dhcp_opts:
        summary += f" IP={dhcp_opts['requested_addr']}"
    if "hostname" in dhcp_opts:
        hn = dhcp_opts["hostname"]
        if isinstance(hn, bytes):
            hn = hn.decode(errors="replace")
        summary += f" host={hn}"
    # BOOTP ciaddr pode ser 0.0.0.0 em Discover — usar src nesse caso
    ciaddr = pkt[BOOTP].ciaddr if BOOTP in pkt else src
    if ciaddr == "0.0.0.0":
        ciaddr = src
    return "DHCP", ciaddr, dst, summary, eth_src, eth_dst


# ─────────────────────────────────────────────
# Callback principal
# ─────────────────────────────────────────────
def packet_callback(pkt, args, iface):
    global packet_counter

    proto, src, dst, summary, mac_src, mac_dst = identify_packet(pkt)

    # ── Filtros ───────────────────────────────
    if args.proto and proto.upper() != args.proto.upper():
        return
    if args.ip:
        pkt_ips = set()
        if IP in pkt:
            pkt_ips.update([pkt[IP].src, pkt[IP].dst])
        if IPv6 in pkt:
            pkt_ips.update([pkt[IPv6].src, pkt[IPv6].dst])
        if args.ip not in pkt_ips:
            return
    if args.mac:
        macs = set()
        if Ether in pkt:
            macs.update([pkt[Ether].src.lower(), pkt[Ether].dst.lower()])
        if args.mac.lower() not in macs:
            return

    # ── Metadados (thread-safe) ───────────────
    with _lock:
        packet_counter        += 1
        n                      = packet_counter
        stats["total"]        += 1
        stats["by_proto"][proto] += 1
        stats["bytes"]        += len(pkt)

    # Usar o timestamp real do pacote (mais preciso que time.time())
    ts_str = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
    size   = len(pkt)

    record = {
        "n":         n,
        "timestamp": ts_str,
        "iface":     iface,
        "proto":     proto,
        "src":       src,
        "dst":       dst,
        "mac_src":   mac_src,
        "mac_dst":   mac_dst,
        "size":      size,
        "summary":   summary,
    }

    # ── Live output ───────────────────────────
    if args.live:
        color = PROTO_COLORS.get(proto, C.RESET)
        print(
            f"{C.GREY}{n:>5}{C.RESET} "
            f"{C.GREY}{ts_str}{C.RESET} "
            f"{color}{proto:<8}{C.RESET} "
            f"{src:<22} → {dst:<22} "
            f"{C.GREY}{size:>5}B{C.RESET}  "
            f"{summary}"
        )

    # ── Logging ───────────────────────────────
    with _lock:
        if log_txt:
            log_txt.write(
                f"[{ts_str}] #{n} {proto:<8} {src} → {dst} | {size}B | {summary}\n"
            )
            log_txt.flush()

        if csv_writer:
            csv_writer.writerow(record)
            log_csv.flush()

        if log_json_path:
            json_records.append(record)


# ─────────────────────────────────────────────
# Estatísticas
# ─────────────────────────────────────────────
def _print_stats():
    with _lock:
        total    = stats["total"]
        nbytes   = stats["bytes"]
        by_proto = dict(stats["by_proto"])
        elapsed  = time.time() - stats["start_time"] if stats["start_time"] else 0

    print(f"\n{C.BOLD}{'─'*50}")
    print(f"  Estatísticas de captura")
    print(f"{'─'*50}{C.RESET}")
    print(f"  Total de pacotes : {total}")
    print(f"  Total de bytes   : {nbytes:,}")
    print(f"  Duração          : {elapsed:.1f}s")
    if elapsed > 0:
        print(f"  Débito médio     : {nbytes / elapsed / 1024:.2f} KB/s")
    print(f"\n  Por protocolo:")
    for p, n in sorted(by_proto.items(), key=lambda x: -x[1]):
        bar = "█" * min(n, 40)
        print(f"    {p:<10} {n:>5}  {bar}")
    print()


# ─────────────────────────────────────────────
# Fecho dos logs
# ─────────────────────────────────────────────
def _close_logs():
    if log_txt:
        log_txt.close()
    if log_csv:
        log_csv.close()
    if log_json_path:
        with open(log_json_path, "w", encoding="utf-8") as f:
            json.dump(json_records, f, indent=2, ensure_ascii=False)
        print(f"[LOG] JSON guardado em {log_json_path}")


# ─────────────────────────────────────────────
# Sinal de interrupção (Ctrl+C)
# ─────────────────────────────────────────────
def handle_sigint(sig, frame):
    print(f"\n{C.BOLD}{C.YELLOW}[*] Captura interrompida.{C.RESET}")
    _stop_stats.set()   # para o thread de estatísticas
    _print_stats()
    _close_logs()
    sys.exit(0)


# ─────────────────────────────────────────────
# Listagem de interfaces
# ─────────────────────────────────────────────
def list_interfaces():
    print(f"\n{C.BOLD}Interfaces disponíveis:{C.RESET}")
    for iface in get_if_list():
        print(f"  • {iface}")
    print()


# ─────────────────────────────────────────────
# Argumentos CLI
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="RC-TP2 Packet Sniffer — Redes de Computadores, UMinho 2025/2026",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-i", "--iface",        default=None, help="Interface de rede (ex: eth0, wlan0)")
    p.add_argument("-n", "--count",        type=int, default=0, help="Nº de pacotes a capturar (0 = infinito)")
    p.add_argument("-f", "--proto",        default=None, help="Filtro por protocolo (ARP, ICMP, DNS, DHCP, HTTP, TCP, UDP, 802.11)")
    p.add_argument("--ip",                 default=None, help="Filtro por endereço IP")
    p.add_argument("--mac",                default=None, help="Filtro por endereço MAC")
    p.add_argument("--bpf",                default=None, help="Filtro BPF (ex: 'tcp port 80')")
    p.add_argument("--live",               action="store_true", default=True, help="Modo live — imprimir na consola [default: ON]")
    p.add_argument("--no-live",            dest="live", action="store_false", help="Desativar modo live")
    p.add_argument("--log-txt",            default=None, help="Guardar log em ficheiro .txt")
    p.add_argument("--log-csv",            default=None, help="Guardar log em ficheiro .csv")
    p.add_argument("--log-json",           default=None, help="Guardar log em ficheiro .json")
    p.add_argument("--list-ifaces",        action="store_true", help="Listar interfaces disponíveis")
    p.add_argument("--stats-interval",     type=int, default=0, help="Mostrar estatísticas de N em N segundos (0 = desativado)")
    return p.parse_args()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    global log_txt, log_csv, csv_writer, log_json_path, stats

    args = parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    # Banner
    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════╗
║          RC-TP2  Packet Sniffer                  ║
║    Redes de Computadores — UMinho 2025/2026      ║
╚══════════════════════════════════════════════════╝{C.RESET}
""")

    iface = args.iface or conf.iface
    print(f"  Interface  : {C.BOLD}{iface}{C.RESET}")
    print(f"  Protocolo  : {args.proto or 'todos'}")
    print(f"  Filtro IP  : {args.ip  or '—'}")
    print(f"  Filtro MAC : {args.mac or '—'}")
    print(f"  Filtro BPF : {args.bpf or '—'}")
    print(f"  Count      : {args.count or '∞'}")

    # Abrir ficheiros de log
    if args.log_txt:
        log_txt = open(args.log_txt, "w", encoding="utf-8")
        log_txt.write(f"# RC-TP2 Packet Sniffer — {datetime.now()}\n")
        print(f"  Log TXT    : {args.log_txt}")

    if args.log_csv:
        log_csv = open(args.log_csv, "w", newline="", encoding="utf-8")
        fieldnames = ["n", "timestamp", "iface", "proto", "src", "dst",
                      "mac_src", "mac_dst", "size", "summary"]
        csv_writer = csv.DictWriter(log_csv, fieldnames=fieldnames)
        csv_writer.writeheader()
        print(f"  Log CSV    : {args.log_csv}")

    if args.log_json:
        log_json_path = args.log_json
        print(f"  Log JSON   : {args.log_json}")

    print(f"\n{C.GREY}{'─'*90}")
    print(f"{'#':>5} {'Hora':<14} {'Proto':<8} {'Origem':<22}   {'Destino':<22} {'Bytes':>6}  Resumo")
    print(f"{'─'*90}{C.RESET}")

    stats["start_time"] = time.time()
    signal.signal(signal.SIGINT, handle_sigint)

    # Thread de estatísticas periódicas
    if args.stats_interval > 0:
        t = threading.Thread(target=_stats_loop, args=(args.stats_interval,), daemon=True)
        t.start()
        print(f"  Stats      : a cada {args.stats_interval}s\n")

    # Captura
    sniff(
        iface=iface,
        filter=args.bpf,
        prn=lambda p: packet_callback(p, args, iface),
        count=args.count if args.count > 0 else 0,
        store=False,
    )

    # Terminou por count
    _stop_stats.set()
    _print_stats()
    _close_logs()


if __name__ == "__main__":
    main()
