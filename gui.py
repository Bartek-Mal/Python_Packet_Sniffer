import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread, Event
from sniffer import start_sniffing
from packet_processing import packet_callback
from hexdump_utils import show_packet_info, import_from_hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.utils import hexdump
import queue

class PacketSnifferApp:
    def __init__(self):
        self.action = None
        self.packet_number = 0
        self.packet_hexdumps = []
        self.packets = []
        self.stop_sniff_event = Event()
        self.window = tk.Tk()
        self.packet_queue = queue.Queue()
        self.setup_gui()
        self.window.after(100, self.process_packets)

    def setup_gui(self):
        self.window.title("Python Packet Sniffer")
        self.window.geometry("1200x600")
        # Style
        style = ttk.Style()
        style.theme_use('clam')

        # Initialize filter variables
        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=True)
        self.icmp_var = tk.BooleanVar(value=True)
        self.arp_var = tk.BooleanVar(value=True)
        self.dns_var = tk.BooleanVar(value=True)

        self.selected_filter = tk.StringVar()
        self.filter_entry = ttk.Entry(width=20)

        # Status variable
        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to Packet Sniffer")

        # Menu Bar
        menu_bar = tk.Menu(self.window)

        # File Menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(
            label="Save",
            command=lambda: self.update_status("Save option selected.")
        )
        file_menu.add_command(
            label="Open",
            command=lambda: self.update_status("Open option selected.")
        )
        file_menu.add_command(
            label="Import from hexdump",
            command=lambda: import_from_hexdump(self)
        )
        file_menu.add_command(label="Quit", command=self.quit_program)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Edit Menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(
            label="Find packet",
            command=lambda: self.update_status("Find packet option selected.")
        )
        edit_menu.add_command(
            label="Find next",
            command=lambda: self.update_status("Find next option selected.")
        )
        edit_menu.add_command(
            label="Find previous",
            command=lambda: self.update_status("Find previous option selected.")
        )
        menu_bar.add_cascade(label="Edit", menu=edit_menu)

        # Filter Menu
        filter_menu = tk.Menu(menu_bar, tearoff=0)
        filter_menu.add_checkbutton(
            label="TCP", variable=self.tcp_var,
            command=lambda: self.update_status(
                "TCP filter " + ("enabled" if self.tcp_var.get() else "disabled")
            )
        )
        filter_menu.add_checkbutton(
            label="UDP", variable=self.udp_var,
            command=lambda: self.update_status(
                "UDP filter " + ("enabled" if self.udp_var.get() else "disabled")
            )
        )
        filter_menu.add_checkbutton(
            label="ICMP", variable=self.icmp_var,
            command=lambda: self.update_status(
                "ICMP filter " + ("enabled" if self.icmp_var.get() else "disabled")
            )
        )
        filter_menu.add_checkbutton(
            label="ARP", variable=self.arp_var,
            command=lambda: self.update_status(
                "ARP filter " + ("enabled" if self.arp_var.get() else "disabled")
            )
        )
        filter_menu.add_checkbutton(
            label="DNS", variable=self.dns_var,
            command=lambda: self.update_status(
                "DNS filter " + ("enabled" if self.dns_var.get() else "disabled")
            )
        )
        menu_bar.add_cascade(label="Filter", menu=filter_menu)

        self.window.config(menu=menu_bar)

        # Interface frame
        frame = ttk.Frame(self.window, padding=(20, 10))
        frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)

        # Filter
        filter_label = ttk.Label(frame, text="Filter:", font=("Arial", 14))
        filter_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

        filter_options = ["Filter", "IP", "Port", "MAC"]
        self.selected_filter.set(filter_options[0])

        filter_choice_box = ttk.OptionMenu(frame, self.selected_filter, *filter_options)
        filter_choice_box.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.filter_entry = ttk.Entry(frame, width=20)
        self.filter_entry.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        # Choose your interface
        interface_label = ttk.Label(frame, text="Choose your interface:", font=("Arial", 14))
        interface_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        interfaces = ["any", "eth0", "wlan0", "lo", "bluetooth0"]
        self.choose_interface = tk.StringVar()
        self.choose_interface.set(interfaces[0])
        interface_choice_box = ttk.OptionMenu(frame, self.choose_interface, *interfaces)
        interface_choice_box.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Control buttons
        button_frame = ttk.Frame(self.window, padding=(10, 5))
        button_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=5)

        start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.sniffing_action)
        start_button.grid(row=0, column=0, padx=10)

        stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing_action)
        stop_button.grid(row=0, column=1, padx=10)

        ok_button = ttk.Button(button_frame, text="OK", command=self.interface_function)
        ok_button.grid(row=0, column=2, padx=10)

        # Output frame
        columns = (
            "#", "Time", "Protocol", "Source MAC/IP", "Destination MAC/IP",
            "Source Port", "Destination Port", "Length"
        )

        tree_frame = ttk.Frame(self.window)
        tree_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree.bind("<Button-1>", self.on_click)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)

        scrollbar = tk.Scrollbar(tree_frame, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.config(yscrollcommand=scrollbar.set)

        # Status bar
        status_bar = ttk.Label(
            self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w'
        )
        status_bar.grid(row=3, column=0, columnspan=3, sticky="ew")

        self.window.grid_rowconfigure(2, weight=1)
        self.window.grid_columnconfigure(0, weight=1)

    def update_status(self, message):
        self.status_var.set(message)

    def sniffing_action(self):
        self.stop_sniff_event.clear()
        self.action = 'sniffing'
        self.update_status("Sniffing started...")

    def stop_sniffing_action(self):
        self.stop_sniff_event.set()
        self.action = 'stop'
        self.update_status("Sniffing stopped.")

    def interface_function(self):
        interface_choice = self.choose_interface.get()
        if self.action:
            self.update_status(f"Selected interface: {interface_choice}")
            if self.action == 'sniffing':
                for item in self.tree.get_children():
                    self.tree.delete(item)

                thread = Thread(
                    target=start_sniffing,
                    args=(
                        interface_choice, self.stop_sniff_event,
                        lambda pkt: packet_callback(pkt, self)
                    )
                )
                thread.daemon = True  
                thread.start()
        else:
            self.update_status("Please select an action.")

    def on_click(self, event):
        selected_item = self.tree.focus()
        if selected_item:
            item_index = int(self.tree.item(selected_item)['values'][0])
            if item_index <= len(self.packets):
                packet = self.packets[item_index - 1]
                packet_show_data = packet.show(dump=True)
                hexdump_data = self.packet_hexdumps[item_index - 1]
                show_packet_info(packet_show_data, hexdump_data)

    def quit_program(self):
        self.window.quit()

    def process_packets(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.process_packet(packet)
        self.window.after(100, self.process_packets)

    def process_packet(self, packet):
        filter_text = self.filter_entry.get().strip()
        src_ip_filter, dst_ip_filter, filter_sport, filter_dport = None, None, None, None
        filter_src_mac, filter_dst_mac = None, None
        sport, dport = None, None
        proto = "Unknown"

        if filter_text:
            if self.selected_filter.get() == "IP":
                if '>' in filter_text:
                    parts = filter_text.split('>')
                    src_ip_filter = parts[0].strip() if parts[0] else None
                    dst_ip_filter = parts[1].strip() if parts[1] else None
                else:
                    src_ip_filter = filter_text
            elif self.selected_filter.get() == "Port":
                if '>' in filter_text:
                    parts = filter_text.split('>')
                    filter_sport = parts[0].strip() if parts[0] else None
                    filter_dport = parts[1].strip() if parts[1] else None
                else:
                    filter_dport = filter_text
            elif self.selected_filter.get() == "MAC":
                if '>' in filter_text:
                    parts = filter_text.split('>')
                    filter_src_mac = parts[0].strip() if parts[0] else None
                    filter_dst_mac = parts[1].strip() if parts[1] else None
                else:
                    filter_src_mac = filter_text

        if ARP in packet and self.arp_var.get():
            proto = "ARP"
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst if hasattr(packet[ARP], 'hwdst') else 'N/A'
            ip_src = packet[ARP].psrc
            ip_dst = packet[ARP].pdst

            self.packet_number += 1
            packet_time = packet.time
            packet_length = len(packet)

            self.filter_packet(
                src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, None, filter_dport, None,
                filter_src_mac, src_mac, filter_dst_mac, dst_mac,
                values=(self.packet_number, packet_time, proto, src_mac, dst_mac, ip_src, ip_dst, packet_length)
            )

        elif IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            self.packet_number += 1
            packet_time = packet.time
            packet_length = len(packet)

            if TCP in packet and self.tcp_var.get():
                port_protocol_map = {80: "HTTP", 443: "HTTPS", 445: "SMB", 23: "Telnet", 21: "FTP"}
                proto = port_protocol_map.get(packet[TCP].dport, port_protocol_map.get(packet[TCP].sport, "TCP"))
                sport = packet[TCP].sport
                dport = packet[TCP].dport

            elif UDP in packet and DNS in packet and self.dns_var.get() and self.udp_var.get():
                proto = "DNS"
                dns = packet[DNS]

                if DNSQR in dns:
                    questions = [q.qname.decode() for q in dns[DNSQR]]
                else:
                    questions = []

                if dns.ancount > 0 and DNSRR in dns:
                    answers = [a.rdata for a in dns[DNSRR]]
                else:
                    answers = []

                self.filter_packet(
                    src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, questions, filter_dport, answers,
                    filter_src_mac, None, filter_dst_mac, None,
                    values=(self.packet_number, packet_time, proto, ip_src, ip_dst, questions, answers, packet_length)
                )
                return

            elif UDP in packet and self.udp_var.get():
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet and self.icmp_var.get():
                proto = "ICMP"
                sport = packet[ICMP].sport if hasattr(packet[ICMP], 'sport') else 'N/A'
                dport = packet[ICMP].dport if hasattr(packet[ICMP], 'dport') else 'N/A'

            self.filter_packet(
                src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, sport, filter_dport, dport,
                filter_src_mac, None, filter_dst_mac, None,
                values=(self.packet_number, packet_time, proto, ip_src, ip_dst, sport, dport, packet_length)
            )

        self.packets.append(packet)
        packet_hexdump = hexdump(packet, dump=True)
        self.packet_hexdumps.append(packet_hexdump)
        
        self.tree.tag_configure('tcp', background='#FFCCCC')
        self.tree.tag_configure('udp', background='#CCFFCC')
        self.tree.tag_configure('icmp', background='#CCCCFF')
        self.tree.tag_configure('dns', background='#FFFFCC')
        self.tree.tag_configure('arp', background='#FFCCFF')
        self.tree.tag_configure('default', background='#FFFFFF')

    def filter_packet(
        self, src_ip_filter, ip_src, dst_ip_filter, ip_dst,
        filter_sport, sport, filter_dport, dport,
        filter_src_mac, src_mac, filter_dst_mac, dst_mac, values
    ):
        src_ip_condition = (not src_ip_filter or ip_src == src_ip_filter)
        dst_ip_condition = (not dst_ip_filter or ip_dst == dst_ip_filter)
        sport_condition = (not filter_sport or str(sport) == filter_sport)
        dport_condition = (not filter_dport or str(dport) == filter_dport)
        src_mac_condition = (not filter_src_mac or src_mac == filter_src_mac)
        dst_mac_condition = (not filter_dst_mac or dst_mac == filter_dst_mac)

        if src_ip_condition and dst_ip_condition and sport_condition and dport_condition and src_mac_condition and dst_mac_condition:
            proto = values[2]

            if proto == "DNS" and self.dns_var.get():
                self.tree.insert("", tk.END, values=values, tags=('dns',))
            elif proto == "UDP" and self.udp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('udp',))
            elif proto == "ICMP" and self.icmp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('icmp',))
            elif proto == "ARP" and self.arp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('arp',))
            elif (proto == "TCP" or proto in ["HTTP", "HTTPS", "SMB", "Telnet", "FTP"]) and self.tcp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('tcp',))

    def run(self):
        self.window.mainloop()
