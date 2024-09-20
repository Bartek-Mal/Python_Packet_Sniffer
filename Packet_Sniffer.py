from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP 
from scapy.layers.l2 import ARP, Ether
import tkinter as tk
from tkinter import ttk
from threading import Thread

action = None
packet_number = 0
packet_hexdumps = []

def sniffing_action():
    global action
    action = 'sniffing'
    update_status("Sniffing started...")

def stop_sniffing_action():
    global action
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
    
    if ARP in packet and arp_var.get():
        proto = "ARP"
        src_mac = packet[ARP].hwsrc  
        dst_mac = packet[ARP].hwdst  
        ip_src = packet[ARP].psrc   
        ip_dst = packet[ARP].pdst  
        
        packet_number += 1
        packet_time = packet.time
        packet_length = len(packet)
        tree.insert("", tk.END, values=(packet_number, packet_time, proto, src_mac, dst_mac, ip_src, ip_dst, packet_length))

    elif IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_number += 1
        
        if TCP in packet and tcp_var.get():
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet and udp_var.get():
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport 
        elif ICMP in packet and icmp_var.get():
            proto = "ICMP"
            sport = packet[ICMP].sport if hasattr(packet[ICMP], 'sport') else 'N/A'
            dport = packet[ICMP].dport if hasattr(packet[ICMP], 'dport') else 'N/A'
        else:
            return
        
        packet_time = packet.time
        packet_length = len(packet)
        tree.insert("", tk.END, values=(packet_number, packet_time, proto, ip_src, ip_dst, sport, dport, packet_length))

    packet_hexdump = hexdump(packet, dump=True)
    packet_hexdumps.append(packet_hexdump)

def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False)

def on_click(event):
    selected_item = tree.focus() 
    if selected_item:
        item_index = int(tree.item(selected_item)['values'][0])  
        if item_index <= len(packet_hexdumps):
            hexdump_data = packet_hexdumps[item_index - 1]
            show_hexdump(hexdump_data)
    
    
def show_hexdump(hexdump_data):
    hexdump_window = tk.Toplevel(window)
    hexdump_window.title("Packet Hexdump")
    hexdump_window.geometry("500x300")

    hexdump_text = tk.Text(hexdump_window, height=20, font=("Courier", 10), wrap="none")
    hexdump_text.insert(tk.END, hexdump_data)
    hexdump_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = tk.Scrollbar(hexdump_window, command=hexdump_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    hexdump_text.config(yscrollcommand=scrollbar.set)
    
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
file_menu.add_separator()
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

filter_menu.add_checkbutton(label="TCP", variable=tcp_var, 
                            command=lambda: update_status("TCP filter " + ("enabled" if tcp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="UDP", variable=udp_var, 
                            command=lambda: update_status("UDP filter " + ("enabled" if udp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="ICMP", variable=icmp_var, 
                            command=lambda: update_status("ICMP filter " + ("enabled" if icmp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="ARP", variable=icmp_var, 
                            command=lambda: update_status("ARP filter " + ("enabled" if arp_var.get() else "disabled")))
menu_bar.add_cascade(label="Filter", menu=filter_menu)

window.config(menu=menu_bar)

# Interface frame
frame = ttk.Frame(window, padding=(20, 10))
frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)

interface_label = ttk.Label(frame, text="Choose your interface:", font=("Arial", 14))
interface_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

interfaces = ["any", "eth0", "wlan0", "lo", "any", "bluetooth0"]
choose_interface = tk.StringVar()
choose_interface.set(interfaces[0])
interface_choice_box = ttk.OptionMenu(frame, choose_interface, *interfaces)
interface_choice_box.grid(row=0, column=1, padx=10, pady=5, sticky="w")

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
