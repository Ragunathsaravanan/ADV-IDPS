
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, Raw, wrpcap, conf, IFACES
import threading
import platform
from bluetooth import bluetooth_tracker
from webtracker import webtracker as web_tracker
from darkwebscraper import darkwebscraper

class PacketCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IDPS SUITE")

        # Packet Sniffer Section
        self.packet_table = ttk.Treeview(root, columns=("Packet", "Source", "Destination", "Protocol"), show="headings")
        self.packet_table.heading("Packet", text="Packet Summary")
        self.packet_table.heading("Source", text="Source")
        self.packet_table.heading("Destination", text="Destination")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.pack(expand=True, fill=tk.BOTH)

        self.packet_table.bind("<Double-1>", self.show_packet_details)

        # Buttons for packet capture
        self.button_frame = tk.Frame(root)
        self.button_frame.pack(fill=tk.X, pady=5)

        self.start_button = tk.Button(self.button_frame, text="Start Capture", command=self.start_capture, bg="green",
                                      fg="white")
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(self.button_frame, text="Stop Capture", command=self.stop_capture, bg="red",
                                     fg="white", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        self.save_button = tk.Button(self.button_frame, text="Save to PCAP", command=self.save_to_pcap,
                                     state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=10)

        # Buttons for extra features
        self.web_tracker_button = tk.Button(self.button_frame, text="Web Tracker", command=self.start_web_tracker,
                                            bg="grey", fg="black")
        self.bluetooth_tracker_button = tk.Button(self.button_frame, text="Start Bluetooth Tracker", command=self.start_bluetooth_tracker,
                                            bg="blue", fg="white")

        self.darkweb_tracker_button = tk.Button(self.button_frame, text="(dark)web scraper", command=self.start_darkweb_scraper,
                                            bg="red", fg="white")
        self.web_tracker_button.pack(side=tk.LEFT, padx=10)
        self.bluetooth_tracker_button.pack(side=tk.LEFT, padx=10)
        self.darkweb_tracker_button.pack(side=tk.LEFT, padx=10)

        # Filters for packet types
        self.filter_frame = tk.LabelFrame(root, text="Filters")
        self.filter_frame.pack(fill=tk.X, padx=10, pady=5)

        self.tcp_var = tk.BooleanVar()
        self.udp_var = tk.BooleanVar()
        self.dns_var = tk.BooleanVar()

        tk.Checkbutton(self.filter_frame, text="TCP", variable=self.tcp_var).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(self.filter_frame, text="UDP", variable=self.udp_var).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(self.filter_frame, text="DNS", variable=self.dns_var).pack(side=tk.LEFT, padx=5)

        # Statistics for packet capture
        self.stats_frame = tk.LabelFrame(root, text="Real-Time Statistics")
        self.stats_frame.pack(fill="both", expand=True)

        self.packet_count_label = tk.Label(self.stats_frame, text="Packets: 0")
        self.packet_count_label.grid(row=0, column=0)

        self.total_tcp_label = tk.Label(self.stats_frame, text="TCP: 0")
        self.total_tcp_label.grid(row=1, column=0)

        self.total_udp_label = tk.Label(self.stats_frame, text="UDP: 0")
        self.total_udp_label.grid(row=2, column=0)

        self.total_dns_label = tk.Label(self.stats_frame, text="DNS: 0")
        self.total_dns_label.grid(row=3, column=0)

        self.packets = []
        self.sniffing = False
        self.interface = self.get_wifi_interface()  # Get the wireless adapter interface

    def get_wifi_interface(self):
        """Get the Wi-Fi adapter interface on Windows"""
        interfaces = [iface.description for iface in IFACES.values()]
        for iface in IFACES.values():
            if "Wi-Fi" in iface.description or "Wireless" in iface.description:
                return iface.name
        return None

    def add_packet(self, packet_summary, source_ip, destination_ip, protocol, packet):
        self.packet_table.insert("", tk.END, values=(packet_summary, source_ip, destination_ip, protocol))
        self.packets.append(packet)
        self.save_button.config(state=tk.NORMAL)
        self.detect_attack(packet)

    def save_to_pcap(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                 filetypes=[("PCAP files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            wrpcap(file_path, self.packets)

    def start_capture(self):
        if not self.interface:
            messagebox.showerror("Error", "No Wi-Fi adapter found! Please ensure Npcap is installed and enabled.")
            return
        self.sniffing = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_capture(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def detect_attack(self, packet):
        """Detect potential attacks based on packet characteristics."""
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            messagebox.showwarning("Potential Attack Detected", "Possible SYN scan detected from: " + packet[IP].src)

        if packet.haslayer(Raw) and b'attack' in packet[Raw].load:
            messagebox.showwarning("Potential Attack Detected",
                                   "Suspicious payload detected in packet from: " + packet[IP].src)

        if packet.haslayer(ARP) and packet[ARP].op == 2:
            messagebox.showwarning("ARP Spoofing Alert",
                                   "Possible ARP spoofing detected! MAC address: " + packet[ARP].hwsrc)

    def capture_packets(self):
        """Capture Wi-Fi packets (Windows - Managed Mode)"""
        sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.sniffing)

    def packet_handler(self, pkt):
        if pkt.haslayer(IP):
            protocol = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'DNS' if pkt.haslayer(
                DNS) else 'Other'
            if (protocol == 'TCP' and not self.tcp_var.get()) or (protocol == 'UDP' and not self.udp_var.get()) or (
                    protocol == 'DNS' and not self.dns_var.get()):
                return
            self.add_packet(pkt.summary(), pkt[IP].src, pkt[IP].dst, protocol, pkt)

    def show_packet_details(self, event):
        selected_item = self.packet_table.selection()
        if not selected_item:
            return
        index = self.packet_table.index(selected_item[0])
        packet = self.packets[index]

        detail_window = tk.Toplevel(self.root)
        detail_window.title("Packet Details")
        text_area = scrolledtext.ScrolledText(detail_window, width=80, height=20)
        text_area.pack(expand=True, fill=tk.BOTH)

        details = f"Packet Summary:\n{packet.summary()}\n\n"
        if packet.haslayer(IP):
            details += f"Source IP: {packet[IP].src}\nDestination IP: {packet[IP].dst}\nTTL: {packet[IP].ttl}\n\n"
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                decoded_data = raw_data.decode(errors='ignore')
                details += f"Decoded Raw Data:\n{decoded_data}\n"
            except:
                details += "Raw Data: Unable to decode\n"

        text_area.insert(tk.END, details)
        text_area.config(state=tk.DISABLED)

    def start_web_tracker(self):
        web_tracker()

    def start_bluetooth_tracker(self):
        bluetooth_tracker()

    def start_darkweb_scraper(self):
        darkwebscraper()


if __name__ == "__main__":
    root = tk.Tk()
    # root.iconbitmap('app.ico')
    gui = PacketCaptureGUI(root)
    root.mainloop()
