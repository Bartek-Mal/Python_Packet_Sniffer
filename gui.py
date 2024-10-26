import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread, Event
from sniffer import start_sniffing
from packet_processing import packet_callback
from hexdump_utils import show_packet_info, import_from_hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether, GRE
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.utils import hexdump
from info import info
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
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Initialize protocol filter variables
        # Application Layer Protocols
        self.http_var = tk.BooleanVar(value=True)
        self.https_var = tk.BooleanVar(value=True)
        self.dns_var = tk.BooleanVar(value=True)
        self.ftp_var = tk.BooleanVar(value=True)
        self.telnet_var = tk.BooleanVar(value=True)
        self.smtp_var = tk.BooleanVar(value=True)
        self.pop3_var = tk.BooleanVar(value=False)
        self.imap_var = tk.BooleanVar(value=False)
        self.smb_var = tk.BooleanVar(value=False)
        self.ntp_var = tk.BooleanVar(value=False)
        self.ssh_var = tk.BooleanVar(value=False)
        self.rdp_var = tk.BooleanVar(value=False)

        # Transport Layer Protocols
        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=True)

        # Network Layer Protocols
        self.icmp_var = tk.BooleanVar(value=True)
        self.arp_var = tk.BooleanVar(value=True)
        self.gre_var = tk.BooleanVar(value=False)

        # Data Link Layer Protocols
        self.ether_var = tk.BooleanVar(value=False)
        self.ppp_var = tk.BooleanVar(value=False)
        self.stp_var = tk.BooleanVar(value=False)
        self.lldp_var = tk.BooleanVar(value=False)

        self.selected_filter = tk.StringVar()
        self.filter_entry = ttk.Entry(width=20)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to Packet Sniffer")
        
        # Menu Bar
        menu_bar = tk.Menu(self.window)
        
        # File Menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Save", command=lambda: self.save())
        file_menu.add_command(label="Open", command=lambda: self.update_status("Open option selected."))
        file_menu.add_command(label="Import from hexdump", command=lambda: import_from_hexdump(self))
        file_menu.add_command(label="Quit", command=self.quit_program)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Edit Menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Find packet", command=lambda: self.update_status("Find packet option selected."))
        edit_menu.add_command(label="Find next", command=lambda: self.update_status("Find next option selected."))
        edit_menu.add_command(label="Find previous", command=lambda: self.update_status("Find previous option selected."))
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        
        # Filter Menu with Protocol Grouping
        filter_menu = tk.Menu(menu_bar, tearoff=0)
        
        # Application Layer Group
        app_layer_menu = tk.Menu(filter_menu, tearoff=0)
        app_layer_menu.add_checkbutton(label="HTTP", variable=self.http_var)
        app_layer_menu.add_checkbutton(label="HTTPS", variable=self.https_var)
        app_layer_menu.add_checkbutton(label="DNS", variable=self.dns_var)
        app_layer_menu.add_checkbutton(label="FTP", variable=self.ftp_var)
        app_layer_menu.add_checkbutton(label="Telnet", variable=self.telnet_var)
        app_layer_menu.add_checkbutton(label="SMTP", variable=self.smtp_var)
        app_layer_menu.add_checkbutton(label="POP3", variable=self.pop3_var)
        app_layer_menu.add_checkbutton(label="IMAP", variable=self.imap_var)
        app_layer_menu.add_checkbutton(label="SMB", variable=self.smb_var)
        app_layer_menu.add_checkbutton(label="NTP", variable=self.ntp_var)
        app_layer_menu.add_checkbutton(label="SSH", variable=self.ssh_var)
        app_layer_menu.add_checkbutton(label="RDP", variable=self.rdp_var)
        filter_menu.add_cascade(label="Application Layer", menu=app_layer_menu)
        
        # Transport Layer Group
        transport_layer_menu = tk.Menu(filter_menu, tearoff=0)
        transport_layer_menu.add_checkbutton(label="TCP", variable=self.tcp_var)
        transport_layer_menu.add_checkbutton(label="UDP", variable=self.udp_var)
        filter_menu.add_cascade(label="Transport Layer", menu=transport_layer_menu)
        
        # Network Layer Group
        network_layer_menu = tk.Menu(filter_menu, tearoff=0)
        network_layer_menu.add_checkbutton(label="ICMP", variable=self.icmp_var)
        network_layer_menu.add_checkbutton(label="ARP", variable=self.arp_var)
        network_layer_menu.add_checkbutton(label="GRE", variable=self.gre_var)
        filter_menu.add_cascade(label="Network Layer", menu=network_layer_menu)

        # Data Link Layer Group
        data_link_layer_menu = tk.Menu(filter_menu, tearoff=0)
        data_link_layer_menu.add_checkbutton(label="Ethernet", variable=self.ether_var)
        data_link_layer_menu.add_checkbutton(label="PPP", variable=self.ppp_var)
        data_link_layer_menu.add_checkbutton(label="STP", variable=self.stp_var)
        data_link_layer_menu.add_checkbutton(label="LLDP", variable=self.lldp_var)
        filter_menu.add_cascade(label="Data Link Layer", menu=data_link_layer_menu)
        
        menu_bar.add_cascade(label="Filter", menu=filter_menu)
        
        # Add INFO button in Menu
        menu_bar.add_command(label="INFO", command=self.info_display)
        
        # Configure menu in main window
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

        # Parse the filter text input for IP, Port, or MAC-based filtering
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

        # Detect ARP packets
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

        # Detect IP-based packets
        elif IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            self.packet_number += 1
            packet_time = packet.time
            packet_length = len(packet)

            # TCP and its associated protocols
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                protocol_map = {
                    80: "HTTP", 443: "HTTPS", 21: "FTP", 23: "Telnet",
                    25: "SMTP", 110: "POP3", 143: "IMAP", 22: "SSH",
                    3389: "RDP", 445: "SMB", 1194: "OpenVPN", 500: "ISAKMP"
                }
                proto = protocol_map.get(dport, protocol_map.get(sport, "TCP"))

            # UDP and DNS/NTP-specific handling
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                protocol_map = {
                    53: "DNS", 123: "NTP", 161: "SNMP", 500: "ISAKMP",
                    67: "DHCP", 68: "DHCP"
                }
                
                if DNS in packet and self.dns_var.get():
                    proto = "DNS"
                    dns = packet[DNS]
                    
                    # Extract DNS questions and answers
                    questions = [q.qname.decode() for q in dns[DNSQR]] if DNSQR in dns else []
                    answers = [a.rdata for a in dns[DNSRR]] if dns.ancount > 0 and DNSRR in dns else []

                    self.filter_packet(
                        src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, questions, filter_dport, answers,
                        filter_src_mac, None, filter_dst_mac, None,
                        values=(self.packet_number, packet_time, proto, ip_src, ip_dst, questions, answers, packet_length)
                    )
                    return  # Exit after processing DNS to prevent further processing

                else:
                    proto = protocol_map.get(dport, protocol_map.get(sport, "UDP"))


            # ICMP detection
            elif ICMP in packet and self.icmp_var.get():
                proto = "ICMP"
                sport = getattr(packet[ICMP], 'sport', 'N/A')
                dport = getattr(packet[ICMP], 'dport', 'N/A')

            # GRE detection
            elif GRE in packet and self.gre_var.get():
                proto = "GRE"

            # Apply packet to filter and update GUI
            self.filter_packet(
                src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, sport, filter_dport, dport,
                filter_src_mac, None, filter_dst_mac, None,
                values=(self.packet_number, packet_time, proto, ip_src, ip_dst, sport, dport, packet_length)
            )

        # Handle Data Link Layer packets directly (Ethernet, PPP, STP, LLDP)
        elif Ether in packet and self.ether_var.get():
            proto = "Ethernet"
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            self.filter_packet(
                None, None, None, None, None, None, None, None,
                src_mac, src_mac, dst_mac, dst_mac,
                values=(self.packet_number, packet.time, proto, src_mac, dst_mac, "-", "-", len(packet))
            )

        # Update packet history and hexdump display
        self.packets.append(packet)
        packet_hexdump = hexdump(packet, dump=True)
        self.packet_hexdumps.append(packet_hexdump)
        
        # Set color tags for different protocols in GUI
        self.tree.tag_configure('tcp', background='#FFCCCC')
        self.tree.tag_configure('udp', background='#CCFFCC')
        self.tree.tag_configure('icmp', background='#CCCCFF')
        self.tree.tag_configure('dns', background='#FFFFCC')
        self.tree.tag_configure('arp', background='#FFCCFF')
        self.tree.tag_configure('http', background='#FFFF99')
        self.tree.tag_configure('https', background='#99FF99')
        self.tree.tag_configure('ftp', background='#FF99FF')
        self.tree.tag_configure('ssh', background='#CCCC99')
        self.tree.tag_configure('rdp', background='#99CCFF')
        self.tree.tag_configure('smtp', background='#FFCC99')
        self.tree.tag_configure('pop3', background='#99FF99')
        self.tree.tag_configure('imap', background='#CC99FF')
        self.tree.tag_configure('telnet', background='#FF9999')
        self.tree.tag_configure('smb', background='#FFFF99')
        self.tree.tag_configure('ntp', background='#FFCC33')
        self.tree.tag_configure('isakmp', background='#FF6699')
        self.tree.tag_configure('gre', background='#9999FF')
        self.tree.tag_configure('ethernet', background='#CCCCCC')
        self.tree.tag_configure('ppp', background='#CCFF99')
        self.tree.tag_configure('stp', background='#FF9999')
        self.tree.tag_configure('lldp', background='#FF99FF')
        self.tree.tag_configure('default', background='#FFFFFF')

    def filter_packet(
        self, src_ip_filter, ip_src, dst_ip_filter, ip_dst,
        filter_sport, sport, filter_dport, dport,
        filter_src_mac, src_mac, filter_dst_mac, dst_mac, values
    ):
        # Check each filtering condition
        src_ip_condition = (not src_ip_filter or ip_src == src_ip_filter)
        dst_ip_condition = (not dst_ip_filter or ip_dst == dst_ip_filter)
        sport_condition = (not filter_sport or str(sport) == filter_sport)
        dport_condition = (not filter_dport or str(dport) == filter_dport)
        src_mac_condition = (not filter_src_mac or src_mac == filter_src_mac)
        dst_mac_condition = (not filter_dst_mac or dst_mac == filter_dst_mac)

        # Only add packet to display if it matches all enabled filters
        if src_ip_condition and dst_ip_condition and sport_condition and dport_condition and src_mac_condition and dst_mac_condition:
            proto = values[2]

            # Assign color tags based on the protocol type
            if proto == "HTTP" and self.http_var.get():
                self.tree.insert("", tk.END, values=values, tags=('http',))
            elif proto == "HTTPS" and self.https_var.get():
                self.tree.insert("", tk.END, values=values, tags=('https',))
            elif proto == "FTP" and self.ftp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('ftp',))
            elif proto == "DNS" and self.dns_var.get():
                self.tree.insert("", tk.END, values=values, tags=('dns',))
            elif proto == "UDP" and self.udp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('udp',))
            elif proto == "ICMP" and self.icmp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('icmp',))
            elif proto == "ARP" and self.arp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('arp',))
            elif proto == "SSH" and self.ssh_var.get():
                self.tree.insert("", tk.END, values=values, tags=('ssh',))
            elif proto == "RDP" and self.rdp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('rdp',))
            elif proto == "SMTP" and self.smtp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('smtp',))
            elif proto == "POP3" and self.pop3_var.get():
                self.tree.insert("", tk.END, values=values, tags=('pop3',))
            elif proto == "IMAP" and self.imap_var.get():
                self.tree.insert("", tk.END, values=values, tags=('imap',))
            elif proto == "Telnet" and self.telnet_var.get():
                self.tree.insert("", tk.END, values=values, tags=('telnet',))
            elif proto == "SMB" and self.smb_var.get():
                self.tree.insert("", tk.END, values=values, tags=('smb',))
            elif proto == "NTP" and self.ntp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('ntp',))
            elif proto == "ISAKMP" and self.isakmp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('isakmp',))
            elif proto == "GRE" and self.gre_var.get():
                self.tree.insert("", tk.END, values=values, tags=('gre',))
            elif proto == "Ethernet" and self.ether_var.get():
                self.tree.insert("", tk.END, values=values, tags=('ethernet',))
            elif proto == "PPP" and self.ppp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('ppp',))
            elif proto == "STP" and self.stp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('stp',))
            elif proto == "LLDP" and self.lldp_var.get():
                self.tree.insert("", tk.END, values=values, tags=('lldp',))
            else:
                self.tree.insert("", tk.END, values=values, tags=('default',))

    def save(self):
        with open('saved.txt', 'w') as saves:
            for hex in self.packet_hexdumps:
                saves.write(hex + "\n\n") 

    def info_display(self):
        info_window = tk.Toplevel()
        info_window.title("Info")
        info_window.geometry("800x600")

        packet_show_text = tk.Text(info_window, height=15, font=("Courier", 10), wrap="none")
        packet_show_text.insert(tk.END, info)
        packet_show_text.pack(fill=tk.BOTH, expand=True)

    def run(self):
        self.window.mainloop()
