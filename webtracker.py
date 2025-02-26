import sys
import threading
import datetime
import sqlite3
from scapy.all import sniff, DNSQR, IP, TCP, Raw
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel 
from PyQt5.QtGui import QIcon



# Database setup
def init_db():
    conn = sqlite3.connect("visited_websites.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            protocol TEXT,
            domain TEXT
        )
    """)
    conn.commit()
    conn.close()


# Insert website into database
def log_website(protocol, domain, ui_log):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect("visited_websites.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO websites (timestamp, protocol, domain) VALUES (?, ?, ?)", (timestamp, protocol, domain))
    conn.commit()
    conn.close()
    ui_log.append(f"[{timestamp}] [{protocol}] {domain}")


# Extract SNI from TLS handshake
def extract_sni(packet):
    try:
        payload = bytes(packet[TCP].payload)
        if b"\x16\x03" in payload:
            index = payload.find(b"\x00\x00") + 2
            if index:
                sni_length = payload[index] * 256 + payload[index + 1]
                sni = payload[index + 2: index + 2 + sni_length].decode(errors="ignore")
                return sni
    except:
        pass
    return None


# Packet handler
def packet_callback(packet, ui_log):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip.startswith("192.168.") or src_ip.startswith("127."):
            return

    if packet.haslayer(DNSQR):  # Capture DNS traffic
        domain = packet[DNSQR].qname.decode()
        log_website("DNS", domain, ui_log)

    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
        payload = packet[Raw].load.decode(errors="ignore")
        if "Host:" in payload:
            host_line = [line for line in payload.split("\n") if "Host:" in line]
            if host_line:
                host = host_line[0].split(":")[1].strip()
                log_website("HTTP", host, ui_log)

    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        sni = extract_sni(packet)
        if sni:
            log_website("HTTPS (SNI)", sni, ui_log)


# Sniffing function
def start_sniffing(ui_log):
    sniff(filter="port 53 or port 80 or port 443", prn=lambda pkt: packet_callback(pkt, ui_log), store=False)


# GUI Application
class NetworkMonitorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.sniff_thread = None
        self.sniffing = False

    def init_ui(self):
        self.setWindowTitle("visited website analyzer")
        # self.setWindowIcon(QIcon('app.ico'))
        self.setGeometry(200, 200, 600, 400)
        layout = QVBoxLayout()
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)

        self.status_label = QLabel("Status: Not Running")
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        layout.addWidget(self.status_label)
        layout.addWidget(self.log_display)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        self.setLayout(layout)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Status: Running")
            self.sniff_thread = threading.Thread(target=start_sniffing, args=(self.log_display,), daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Status: Stopped")
            QApplication.instance().quit()  # Use this instead of sys.exit()


def webtracker():
    init_db()
    app = QApplication([])
    window = NetworkMonitorApp()
    window.show()
    app.exec_()
