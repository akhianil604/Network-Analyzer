import psutil
import time
import socket
import curses
import os
from collections import defaultdict
from datetime import datetime

# Try importing Scapy for bandwidth monitoring (if available)
try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True  # Set to True if Scapy is available
except ImportError:
    SCAPY_AVAILABLE = False  # Set to False if Scapy is not available

# Initialize global dictionaries for storing active connections and bandwidth usage
connections, bandwidth = {}, defaultdict(int)

def resolve(ip, port, resolve_hostnames, resolve_services):
    """
    Resolves IP and port to hostname and service name.
    If resolve_hostnames or resolve_services is False, returns raw IP or port instead.
    """
    host = socket.gethostbyaddr(ip)[0] if resolve_hostnames else ip  # Resolve host to hostname if enabled
    service = socket.getservbyport(port) if resolve_services else str(port)  # Resolve port to service if enabled
    return host, service

def get_active_connections(resolve_hostnames, resolve_services):
    """
    Gets a dictionary of active TCP connections using psutil.
    Each key is a tuple of (local_ip, local_port, remote_ip, remote_port), and the value is connection info.
    """
    conns = psutil.net_connections(kind='tcp')  # Get active TCP connections
    return {
        (c.laddr.ip, c.laddr.port, c.raddr.ip if c.raddr else '', c.raddr.port if c.raddr else 0): {
            'pid': c.pid or 0,  # Process ID associated with the connection
            'status': c.status,  # Current status of the connection (e.g., ESTABLISHED, TIME_WAIT)
            'process': psutil.Process(c.pid).name() if c.pid else '',  # Process name for the given PID
            'local': resolve(c.laddr.ip, c.laddr.port, resolve_hostnames, resolve_services),  # Resolve local address
            'remote': resolve(c.raddr.ip, c.raddr.port, resolve_hostnames, resolve_services) if c.raddr else ('', '')  # Resolve remote address
        }
        for c in conns if c.status != psutil.CONN_NONE  # Filter out invalid connections (status is not NONE)
    }

def draw_ui(stdscr, new, closed, active, resolve_hostnames, resolve_services):
    """
    Draws the terminal user interface (UI) to display active, new, and closed connections.
    Displays connection details and bandwidth usage if available.
    """
    stdscr.clear()  # Clear the screen
    max_y, max_x = stdscr.getmaxyx()  # Get the size of the terminal window (rows, columns)
    
    # Display current time and number of active connections at the top of the screen
    stdscr.addstr(0, 0, f"[{datetime.now().strftime('%H:%M:%S')}] Connections: {len(active)}", curses.A_BOLD)
    
    y = 2  # Start drawing at row 2
    # Define sections for new, closed, and active connections
    sections = [("NEW", new, curses.color_pair(2)), ("CLOSED", closed, curses.color_pair(1)), ("ACTIVE", active, curses.A_NORMAL)]
    
    # Draw each section (new, closed, active) of connections
    for label, data, color in sections:
        for k in data:
            if y >= max_y - 1:  # Stop if we've reached the bottom of the screen
                break
            info = data[k]
            lhost, lport = info['local']  # Local host and port
            rhost, rport = info['remote']  # Remote host and port
            line = f"{label:<7} {info['status']:<13} {lhost}:{lport:<5} -> {rhost}:{rport:<5} {info['process']}"  # Format connection info
            if len(line) >= max_x:  # Truncate line if it's too long
                line = line[:max_x - 1]
            stdscr.addstr(y, 0, line, color)  # Add the line to the screen with specified color
            y += 1  # Move to the next line

    # If running as root and bandwidth data is available, display bandwidth usage
    if os.geteuid() == 0 and bandwidth and y < max_y - 2:
        stdscr.addstr(y + 1, 0, "--- Bandwidth Usage (bytes/sec) ---", curses.A_UNDERLINE)
        y += 2  # Move to the next line after the header
        for ip, bytes_count in bandwidth.items():
            if y >= max_y - 1:  # Stop if we've reached the bottom of the screen
                break
            stdscr.addstr(y, 0, f"{ip:<15} : {bytes_count}")  # Display bandwidth usage for each IP
            y += 1  # Move to the next line
    stdscr.refresh()  # Refresh the screen to update UI

def bandwidth_sniffer(pkt):
    """
    Sniffer function for monitoring bandwidth usage.
    This function is called whenever a packet is captured by Scapy.
    """
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):  # Only process TCP packets with an IP layer
        src = pkt['IP'].src  # Get the source IP address
        bandwidth[src] += len(pkt)  # Increment the bandwidth usage for this IP by the packet length

def run_monitor(stdscr):
    """
    Runs the connection monitoring process using curses for UI.
    Periodically checks active connections and updates the UI.
    """
    curses.curs_set(0)  # Hide the cursor
    curses.start_color()  # Start color support in curses
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)  # Define color pair for 'CLOSED' connections (red)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Define color pair for 'NEW' connections (green)

    resolve_hostnames = False  # Disable hostname resolution by default
    resolve_services = False  # Disable service resolution by default

    prev_conns = {}  # Store the previous state of connections for comparison

    # If running as root and Scapy is available, start the bandwidth sniffer in a separate thread
    if os.geteuid() == 0 and SCAPY_AVAILABLE:
        from threading import Thread
        Thread(target=sniff, kwargs={'prn': bandwidth_sniffer, 'store': 0}, daemon=True).start()

    # Main loop to monitor and display connections
    while True:
        try:
            curr_conns = get_active_connections(resolve_hostnames, resolve_services)  # Get current active connections
            new = {k: v for k, v in curr_conns.items() if k not in prev_conns}  # Find new connections
            closed = {k: v for k, v in prev_conns.items() if k not in curr_conns}  # Find closed connections
            draw_ui(stdscr, new, closed, curr_conns, resolve_hostnames, resolve_services)  # Update UI
            prev_conns = curr_conns  # Store current connections for the next iteration
            time.sleep(1)  # Wait for 1 second before the next update
        except KeyboardInterrupt:
            break  # Exit the loop on keyboard interrupt

def start_monitor():
    """
    Starts the connection monitor.
    This function is called when the script is executed.
    """
    print("Starting TCP connection monitor...")
    print("Press Ctrl+C to stop.")
    try:
        curses.wrapper(run_monitor)  # Initialize curses and run the monitor
    except KeyboardInterrupt:
        print("\nMonitor stopped.")  # Print a message when the monitor is stopped

if __name__ == "__main__":
    """
    Main entry point for the script.
    Starts the connection monitor when the script is executed.
    """
    try:
        curses.wrapper(run_monitor)  # Initialize curses and run the monitor
    except KeyboardInterrupt:
        print("\nMonitor stopped.")  # Print a message when the monitor is stopped
