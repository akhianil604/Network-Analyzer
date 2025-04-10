import psutil
import time
import socket
import curses
import os
from collections import defaultdict
from datetime import datetime

# Optional bandwidth monitoring
try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

connections, bandwidth = {}, defaultdict(int)

def resolve(ip, port, resolve_hostnames, resolve_services):
    host = socket.gethostbyaddr(ip)[0] if resolve_hostnames else ip
    service = socket.getservbyport(port) if resolve_services else str(port)
    return host, service

def get_active_connections(resolve_hostnames, resolve_services):
    conns = psutil.net_connections(kind='tcp')
    return {
        (c.laddr.ip, c.laddr.port, c.raddr.ip if c.raddr else '', c.raddr.port if c.raddr else 0): {
            'pid': c.pid or 0,
            'status': c.status,
            'process': psutil.Process(c.pid).name() if c.pid else '',
            'local': resolve(c.laddr.ip, c.laddr.port, resolve_hostnames, resolve_services),
            'remote': resolve(c.raddr.ip, c.raddr.port, resolve_hostnames, resolve_services) if c.raddr else ('', '')
        }
        for c in conns if c.status != psutil.CONN_NONE
    }

def draw_ui(stdscr, new, closed, active, resolve_hostnames, resolve_services):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    stdscr.addstr(0, 0, f"[{datetime.now().strftime('%H:%M:%S')}] Connections: {len(active)}", curses.A_BOLD)
    y = 2
    sections = [("NEW", new, curses.color_pair(2)), ("CLOSED", closed, curses.color_pair(1)), ("ACTIVE", active, curses.A_NORMAL)]
    for label, data, color in sections:
        for k in data:
            if y >= max_y - 1:
                break  
            info = data[k]
            lhost, lport = info['local']
            rhost, rport = info['remote']
            line = f"{label:<7} {info['status']:<13} {lhost}:{lport:<5} -> {rhost}:{rport:<5} {info['process']}"
            if len(line) >= max_x:
                line = line[:max_x - 1]  # Truncate if too wide
            stdscr.addstr(y, 0, line, color)
            y += 1

    if os.geteuid() == 0 and bandwidth and y < max_y - 2:
        stdscr.addstr(y + 1, 0, "--- Bandwidth Usage (bytes/sec) ---", curses.A_UNDERLINE)
        y += 2
        for ip, bytes_count in bandwidth.items():
            if y >= max_y - 1:
                break
            stdscr.addstr(y, 0, f"{ip:<15} : {bytes_count}")
            y += 1
    stdscr.refresh()

def bandwidth_sniffer(pkt):
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        src = pkt['IP'].src
        bandwidth[src] += len(pkt)

def run_monitor(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

    resolve_hostnames = False
    resolve_services = False

    prev_conns = {}

    if os.geteuid() == 0 and SCAPY_AVAILABLE:
        from threading import Thread
        Thread(target=sniff, kwargs={'prn': bandwidth_sniffer, 'store': 0}, daemon=True).start()

    while True:
        try:
            curr_conns = get_active_connections(resolve_hostnames, resolve_services)
            new = {k: v for k, v in curr_conns.items() if k not in prev_conns}
            closed = {k: v for k, v in prev_conns.items() if k not in curr_conns}
            draw_ui(stdscr, new, closed, curr_conns, resolve_hostnames, resolve_services)
            prev_conns = curr_conns
            time.sleep(1)
        except KeyboardInterrupt:
            break

def start_monitor():
    print("Starting TCP connection monitor...")
    print("Press Ctrl+C to stop.")
    try:
        curses.wrapper(run_monitor)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
        
if __name__ == "__main__":
    try:
        curses.wrapper(run_monitor)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")