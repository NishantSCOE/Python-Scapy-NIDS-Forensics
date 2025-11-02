import scapy.all as scapy
import sqlite3
import threading
import time
from collections import defaultdict, Counter
import netifaces
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from multiprocessing import Process, Pipe

LOG_FILE = "packet_log.txt"
DB_FILE = "packets.db"
ALERT_FILE = "alerts.log"

PORT_SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 100
TIME_WINDOW = 10

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_packet(src, dst, sport, dport, proto, length, flags):
    log_entry = f"[{time.ctime()}] {src}:{sport} -> {dst}:{dport} | Proto: {proto} | Len: {length} | Flags: {flags}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def db_insert_packet(src, dst, sport, dport, proto, length, flags):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO packets (source_ip, dest_ip, source_port, dest_port, protocol, length, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (src, dst, sport, dport, proto, length, flags))
    conn.commit()
    conn.close()

packet_counts = defaultdict(list)
port_scan_tracker = defaultdict(set)

def detect_anomalies(source_ip, dest_port):
    current_time = time.time()

    if dest_port:
        port_scan_tracker[source_ip].add(dest_port)
        if len(port_scan_tracker[source_ip]) > PORT_SCAN_THRESHOLD:
            send_alert(f"Port scan detected from {source_ip}. Scanned ports: {port_scan_tracker[source_ip]}")
            port_scan_tracker[source_ip].clear()

    packet_counts[source_ip].append(current_time)
    packet_counts[source_ip] = [t for t in packet_counts[source_ip] if current_time - t < TIME_WINDOW]

    if len(packet_counts[source_ip]) > FLOOD_THRESHOLD:
        send_alert(f"Possible flood detected from {source_ip}. Packet count: {len(packet_counts[source_ip])} in {TIME_WINDOW}s")
        packet_counts[source_ip] = []


def send_alert(message):
    alert_entry = f"[{time.ctime()}] ALERT: {message}\n"
    print(alert_entry)
    with open(ALERT_FILE, "a") as f:
        f.write(alert_entry)

def get_traffic_summary():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM packets")
    total_packets = c.fetchone()[0]

    c.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
    protocol_counts = c.fetchall()

    c.execute("SELECT source_ip, COUNT(*) FROM packets GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 5")
    top_sources = c.fetchall()

    c.execute("SELECT dest_ip, COUNT(*) FROM packets GROUP BY dest_ip ORDER BY COUNT(*) DESC LIMIT 5")
    top_dests = c.fetchall()

    conn.close()

    return {
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "top_sources": top_sources,
        "top_dests": top_dests
    }

def print_summary():
    summary = get_traffic_summary()
    print("\n--- Traffic Summary ---")
    print(f"Total Packets Captured: {summary['total_packets']}")
    print("\nProtocol Breakdown:")
    for proto, count in summary['protocol_counts']:
        print(f"  - {proto}: {count}")
    print("\nTop 5 Source IPs:")
    for ip, count in summary['top_sources']:
        print(f"  - {ip}: {count}")
    print("\nTop 5 Destination IPs:")
    for ip, count in summary['top_dests']:
        print(f"  - {ip}: {count}")
    print("-----------------------\n")

summary_thread = None

def live_summary(interval):
    global summary_thread
    print_summary()
    summary_thread = threading.Timer(interval, live_summary, [interval])
    summary_thread.start()

def update_graph(frame, ax, conn):
    if conn.poll():
        timestamps, packet_counts = conn.recv()
        ax.clear()
        ax.plot(timestamps, packet_counts)
        ax.set_xlabel("Time")
        ax.set_ylabel("Packet Count")
        ax.set_title("Live Traffic")

def live_traffic_graph(conn):
    fig, ax = plt.subplots()
    ani = animation.FuncAnimation(fig, update_graph, fargs=(ax, conn,), interval=1000)
    plt.show()

def get_default_interface():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface != 'lo':
            return interface
    return None

timestamps = []
packet_counts = []
def send_graph_data(conn):
    timestamps.append(time.time())
    packet_counts.append(len(timestamps))
    conn.send((timestamps, packet_counts))

def process_packet(packet, conn=None):
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "Other"
        source_port, dest_port, flags = None, None, ""
        length = len(packet)

        if packet.haslayer(scapy.TCP):
            tcp_layer = packet.getlayer(scapy.TCP)
            proto = "TCP"
            source_port = tcp_layer.sport
            dest_port = tcp_layer.dport
            flags = str(tcp_layer.flags)

        elif packet.haslayer(scapy.UDP):
            udp_layer = packet.getlayer(scapy.UDP)
            proto = "UDP"
            source_port = udp_layer.sport
            dest_port = udp_layer.dport

        elif packet.haslayer(scapy.ICMP):
            proto = "ICMP"

        log_packet(src, dst, source_port, dest_port, proto, length, flags)
        db_insert_packet(src, dst, source_port, dest_port, proto, length, flags)
        detect_anomalies(src, dest_port)

        if conn:
            send_graph_data(conn)

def start_sniffer(interface=None, summary_interval=10, show_graph=False):
    print("Starting packet sniffer...")
    if not interface:
        interface = get_default_interface()
        if not interface:
            print("Could not determine default interface. Please specify one.")
            return
        print(f"Using default interface: {interface}")

    setup_database()
    if summary_interval > 0:
        live_summary(summary_interval)

    graph_proc, conn = None, None
    if show_graph:
        parent_conn, child_conn = Pipe()
        graph_proc = Process(target=live_traffic_graph, args=(child_conn,))
        graph_proc.start()
        conn = parent_conn

    try:
        print("Sniffing... Press Ctrl+C to stop.")
        scapy.sniff(iface=interface, prn=lambda p: process_packet(p, conn), store=False)
    except Exception as e:
        print(f"An error occurred during sniffing: {e}")
    finally:
        if summary_thread:
            summary_thread.cancel()
        if graph_proc:
            graph_proc.terminate()
            graph_proc.join()
        print_summary()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A simple network packet sniffer with anomaly detection.")
    parser.add_argument("--interface", help="The network interface to sniff on.")
    parser.add_argument("--summary-interval", type=int, default=10, help="The interval in seconds for printing the traffic summary.")
    parser.add_argument("--show-graph", action="store_true", help="Show a live traffic graph.")
    args = parser.parse_args()

    start_sniffer(interface=args.interface, summary_interval=args.summary_interval, show_graph=args.show_graph)