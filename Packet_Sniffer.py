from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP 
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR 
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread, Event

action = None
packet_number = 0
packet_hexdumps = []
packets = []
stop_sniff_event = Event()


def sniffing_action():
    global action, stop_sniff_event
    stop_sniff_event.clear() 
    action = 'sniffing'
    update_status("Sniffing started...")

def stop_sniffing_action():
    global action, stop_sniff_event
    stop_sniff_event.set()
    action = 'stop'
    update_status("Sniffing stopped.")

def interface_function():
    interface_dropbox_choice = choose_interface.get()
    if action:
        update_status(f"Selected interface: {interface_dropbox_choice}")
        if action == 'sniffing':
            for item in tree.get_children():
                tree.delete(item)
                
            thread = Thread(target=start_sniffing, args=(interface_dropbox_choice,))
            thread.start()
    else:
        update_status("Please select an action.")
    
def packet_callback(packet):
    global packet_number

    # Get the filter values from the GUI
    filter_text = filter_entry.get().strip()
    src_ip_filter, dst_ip_filter, filter_sport, filter_dport = None, None, None, None
    filter_src_mac, filter_dst_mac = None, None

    # Parse the filter text based on selected filter type
    if filter_text:
        if selected_filter.get() == "IP":
            if '>' in filter_text:
                parts = filter_text.split('>')
                src_ip_filter = parts[0].strip() if parts[0] else None
                dst_ip_filter = parts[1].strip() if parts[1] else None
            else:
                src_ip_filter = filter_text
        elif selected_filter.get() == "Port":
            if '>' in filter_text:
                parts = filter_text.split('>')
                filter_sport = parts[0].strip() if parts[0] else None
                filter_dport = parts[1].strip() if parts[1] else None
            else:
                filter_dport = filter_text
        elif selected_filter.get() == "MAC":
            if '>' in filter_text:
                parts = filter_text.split('>')
                filter_src_mac = parts[0].strip() if parts[0] else None
                filter_dst_mac = parts[1].strip() if parts[1] else None
            else:
                filter_src_mac = filter_text

    if ARP in packet and arp_var.get():
        proto = "ARP"
        src_mac = packet[ARP].hwsrc  
        dst_mac = packet[ARP].hwdst  
        ip_src = packet[ARP].psrc   
        ip_dst = packet[ARP].pdst  
        
        packet_number += 1
        packet_time = packet.time
        packet_length = len(packet)

        filter(src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, None, filter_dport, None, 
               filter_src_mac, src_mac, filter_dst_mac, dst_mac, 
               values=(packet_number, packet_time, proto , src_mac, dst_mac, ip_src, ip_dst, packet_length))
        
    elif IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        packet_number += 1
        packet_time = packet.time
        packet_length = len(packet)

        if TCP in packet and tcp_var.get():
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet and DNS in packet and dns_var.get() and udp_var.get():
            proto = "DNS"
            dns = packet[DNS]
            # transaction_id = dns.id
            questions = [q.qname.decode() for q in dns[DNSQR]] 
            answers = [a.rdata for a in dns[DNSRR]] if dns.ancount > 0 else []
            filter(src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, questions, filter_dport, answers,
                filter_src_mac, None, filter_dst_mac, None, 
                values=(packet_number, packet_time, proto, ip_src, ip_dst, questions, answers, packet_length))
            return 
        elif UDP in packet and udp_var.get():
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet and icmp_var.get():
            proto = "ICMP"
            sport = packet[ICMP].sport if hasattr(packet[ICMP], 'sport') else 'N/A'
            dport = packet[ICMP].dport if hasattr(packet[ICMP], 'dport') else 'N/A'
        filter(src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, sport, filter_dport, dport,
                filter_src_mac, None, filter_dst_mac, None, 
                values=(packet_number, packet_time, proto, ip_src, ip_dst, sport, dport, packet_length))
    packets.append(packet)
    packet_hexdump = hexdump(packet, dump=True)
    packet_hexdumps.append(packet_hexdump)

    
def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_sniff_event.is_set())

def filter(src_ip_filter, ip_src, dst_ip_filter, ip_dst, filter_sport, sport, filter_dport, dport, filter_src_mac, src_mac, filter_dst_mac, dst_mac, values):
    src_ip_condition = (not src_ip_filter or ip_src == src_ip_filter)
    
    dst_ip_condition = (not dst_ip_filter or ip_dst == dst_ip_filter)
    
    sport_condition = (not filter_sport or sport == filter_sport)
    
    dport_condition = (not filter_dport or dport == filter_dport)
    
    src_mac_condition = (not filter_src_mac or src_mac == filter_src_mac)
    
    dst_mac_condition = (not filter_dst_mac or dst_mac == filter_dst_mac)

    if src_ip_condition and dst_ip_condition and sport_condition and dport_condition and src_mac_condition and dst_mac_condition:
        tree.insert("", tk.END, values=values)


def on_click(event):
    selected_item = tree.focus()
    if selected_item:
        item_index = int(tree.item(selected_item)['values'][0])
        if item_index <= len(packets): 
            packet = packets[item_index - 1]
            packet_show_data = packet.show(dump=True)
            hexdump_data = packet_hexdumps[item_index - 1]
            show_packet_info(packet_show_data, hexdump_data)


def show_packet_info(packet_show_data, hexdump_data):
    packet_window = tk.Toplevel(window)
    packet_window.title("Packet Details and Hexdump")
    packet_window.geometry("800x600")

    # Packet infos
    packet_show_label = tk.Label(packet_window, text="Packet Details:")
    packet_show_label.pack()

    packet_show_text = tk.Text(packet_window, height=15, font=("Courier", 10), wrap="none")
    packet_show_text.insert(tk.END, packet_show_data)
    packet_show_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    # Hexdump
    hexdump_label = tk.Label(packet_window, text="Packet Hexdump:")
    hexdump_label.pack()

    hexdump_text = tk.Text(packet_window, height=15, font=("Courier", 10), wrap="none")
    hexdump_text.insert(tk.END, hexdump_data)
    hexdump_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(packet_window, command=packet_show_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    packet_show_text.config(yscrollcommand=scrollbar.set)

    scrollbar2 = tk.Scrollbar(packet_window, command=hexdump_text.yview)
    scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    hexdump_text.config(yscrollcommand=scrollbar2.set)

def import_from_hexdump():
    import_from_hexdump_window = tk.Toplevel(window)
    import_from_hexdump_window.title("Import from hexdump...")
    import_from_hexdump_window.geometry("800x600")
    
    hexdump_insert_label = tk.Label(import_from_hexdump_window, text="Hexdump:")
    hexdump_insert_label.pack()
    
    import_from_hexdump_text = tk.Text(import_from_hexdump_window, height=15, font=("Courier", 10), wrap="none")
    import_from_hexdump_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    scrollbar = tk.Scrollbar(import_from_hexdump_window, command=import_from_hexdump_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    import_from_hexdump_text.config(yscrollcommand=scrollbar.set)
    
    button = ttk.Button(import_from_hexdump_window, text="Process Hexdump", command=lambda: hexdump_interpreter(import_from_hexdump_text.get("1.0", tk.END), packet_info_from_hex_text))
    button.pack(pady=10) 
    
    packet_info_from_hex = tk.Label(import_from_hexdump_window, text="Packet info:")
    packet_info_from_hex.pack()

    packet_info_from_hex_text = tk.Text(import_from_hexdump_window, height=15, font=("Courier", 10), wrap="none")
    
    packet_info_from_hex_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    scrollbar2 = tk.Scrollbar(import_from_hexdump_window, command=packet_info_from_hex_text.yview)
    scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    packet_info_from_hex_text.config(yscrollcommand=scrollbar.set)

def hexdump_interpreter(hexdump_input, packet_info):
    hexdump_input = hexdump_input.strip() 

    if hexdump_input in packet_hexdumps:
        hexdump_index = packet_hexdumps.index(hexdump_input)
        if hexdump_index < len(packets):
            packet = packets[hexdump_index]
            packet_show_data = packet.show(dump=True)
            packet_info.insert(tk.END, packet_show_data)
        else:
            messagebox.showerror("Error", "Hexdump out of bounds!")
    else:
        messagebox.showerror("Error", "Hexdump not found!")
        
def update_status(message):
    status_var.set(message)

def quit_program():
    window.quit()

# GUI Setup

window = tk.Tk()
window.title("Python Packet Sniffer")
window.geometry("1200x600")

# Style
style = ttk.Style()
style.theme_use('clam')

# Menu Bar
menu_bar = tk.Menu(window)

file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Save", command=lambda: update_status("Save option selected."))
file_menu.add_command(label="Open", command=lambda: update_status("Open option selected."))
file_menu.add_command(label="Import from hexdump", command=lambda : import_from_hexdump())
file_menu.add_command(label="Quit", command=quit_program)
menu_bar.add_cascade(label="File", menu=file_menu)

edit_menu = tk.Menu(menu_bar, tearoff=0)
edit_menu.add_command(label="Find packet", command=lambda: update_status("Find packet option selected."))
edit_menu.add_command(label="Find next", command=lambda: update_status("Find next option selected."))
edit_menu.add_command(label="Find previous", command=lambda: update_status("Find previous option selected."))
menu_bar.add_cascade(label="Edit", menu=edit_menu)

filter_menu = tk.Menu(menu_bar, tearoff=0)
tcp_var = tk.BooleanVar(value=True)
udp_var = tk.BooleanVar(value=True)
icmp_var = tk.BooleanVar(value=True)
arp_var = tk.BooleanVar(value=True)
dns_var = tk.BooleanVar(value=True)

filter_menu.add_checkbutton(label="TCP", variable=tcp_var, 
                            command=lambda: update_status("TCP filter " + ("enabled" if tcp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="UDP", variable=udp_var, 
                            command=lambda: update_status("UDP filter " + ("enabled" if udp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="ICMP", variable=icmp_var, 
                            command=lambda: update_status("ICMP filter " + ("enabled" if icmp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="ARP", variable=arp_var, 
                            command=lambda: update_status("ARP filter " + ("enabled" if arp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="DNS", variable=dns_var, 
                            command=lambda: update_status("DNS filter " + ("enabled" if dns_var.get() else "disabled")))
menu_bar.add_cascade(label="Filter", menu=filter_menu)

window.config(menu=menu_bar)

# Interface frame
frame = ttk.Frame(window, padding=(20, 10))
frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)

# Filter
filter_label = ttk.Label(frame, text="Filter:", font=("Arial", 14))
filter_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

filter_options = ["Filter", "IP", "Port", "MAC"]
selected_filter = tk.StringVar()
selected_filter.set(filter_options[0])

filter_choice_box = ttk.OptionMenu(frame, selected_filter, *filter_options)
filter_choice_box.grid(row=0, column=1, padx=10, pady=5, sticky="w")

filter_entry = ttk.Entry(frame, width=20)
filter_entry.grid(row=0, column=2, padx=10, pady=5, sticky="w")

# Choose your interface 
interface_label = ttk.Label(frame, text="Choose your interface:", font=("Arial", 14))
interface_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

interfaces = ["any", "any", "eth0", "wlan0", "lo", "bluetooth0"]
choose_interface = tk.StringVar()
choose_interface.set(interfaces[0])
interface_choice_box = ttk.OptionMenu(frame, choose_interface, *interfaces)
interface_choice_box.grid(row=1, column=1, padx=10, pady=5, sticky="w")


# Control buttons
button_frame = ttk.Frame(window, padding=(10, 5))
button_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=5)

start_button = ttk.Button(button_frame, text="Start Sniffing", command=sniffing_action)
start_button.grid(row=0, column=0, padx=10)

stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing_action)
stop_button.grid(row=0, column=1, padx=10)

ok_button = ttk.Button(button_frame, text="OK", command=interface_function)
ok_button.grid(row=0, column=2, padx=10)

# Output frame
columns = ("#", "Time", "Protocol", "Source MAC/IP", "Destination MAC/IP", "Source Port", "Destination Port", "Length")

tree_frame = ttk.Frame(window)
tree_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)

tree = ttk.Treeview(tree_frame, columns = columns, show = "headings", height=20)
tree.pack(side=tk.LEFT, fill = tk.BOTH, expand=True)

tree.bind("<Button-1>",on_click)

tree.heading("#", text="#")
tree.heading("Time", text="Time")
tree.heading("Protocol", text="Protocol")
tree.heading("Source MAC/IP", text="Source MAC/IP")
tree.heading("Destination MAC/IP", text="Destination MAC/IP")
tree.heading("Source Port", text="Source Port")
tree.heading("Destination Port", text="Destination Port")
tree.heading("Length", text="Length")

tree.column("#", width=50)
tree.column("Time", width=150)
tree.column("Protocol", width=100)
tree.column("Source MAC/IP", width=200)
tree.column("Destination MAC/IP", width=200)
tree.column("Source Port", width=100)
tree.column("Destination Port", width=100)
tree.column("Length", width=80)

scrollbar = tk.Scrollbar(tree_frame, command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.config(yscrollcommand=scrollbar.set)

# Status bar
status_var = tk.StringVar()
status_var.set("Welcome to Packet Sniffer")

status_bar = ttk.Label(window, textvariable=status_var, relief=tk.SUNKEN, anchor='w')
status_bar.grid(row=3, column=0, columnspan=3, sticky="ew")
window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(0, weight=1)

# Event loop
window.mainloop()
