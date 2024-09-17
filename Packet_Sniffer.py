from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP 
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
    action = None
    update_status("Sniffing stopped.")

def interface_function():
    interface_dropbox_choice = choose_interface.get()
    if action:
        output_text.insert(tk.END, f"Selected interface: {interface_dropbox_choice}\n")
        output_text.insert(tk.END, f"Action: {action}\n")
        if action == 'sniffing':
            output_text.delete(1.0, tk.END)
            thread = Thread(target=start_sniffing, args=(interface_dropbox_choice,))
            thread.start()
    else:
        update_status("Please select an action.")
    
def packet_callback(packet):
    global packet_number
    
    if IP in packet:
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
            sport = packet[ICMP].sport
            dport = packet[ICMP].dport 
        else:
            return
            
        packet_info = f"#{packet_number}. Protocol: {proto} | Source: {ip_src}:{sport} -> Destination: {ip_dst}:{dport}\n"
        output_text.insert(tk.END, packet_info)
        output_text.yview(tk.END)

        packet_hexdump = hexdump(packet, dump=True)
        packet_hexdumps.append(packet_hexdump)

def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False)

def on_click(event):
    index = output_text.index(f"@{event.x},{event.y}")
    line_number = int(index.split('.')[0]) 

    if line_number <=len(packet_hexdumps):
        hexdump_data = packet_hexdumps[line_number - 1]
        show_hexdump(hexdump_data)
    else:
        print("No packet found for this line")
    
    
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
window.geometry("800x600")

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

filter_menu.add_checkbutton(label="TCP", variable=tcp_var, 
                            command=lambda: update_status("TCP filter " + ("enabled" if tcp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="UDP", variable=udp_var, 
                            command=lambda: update_status("UDP filter " + ("enabled" if udp_var.get() else "disabled")))
filter_menu.add_checkbutton(label="ICMP", variable=icmp_var, 
                            command=lambda: update_status("ICMP filter " + ("enabled" if icmp_var.get() else "disabled")))
menu_bar.add_cascade(label="Filter", menu=filter_menu)

window.config(menu=menu_bar)

# Interface frame
frame = ttk.Frame(window, padding=(20, 10))
frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)

interface_label = ttk.Label(frame, text="Choose your interface:", font=("Arial", 14))
interface_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

interfaces = ["eth0", "wlan0", "lo", "any", "bluetooth0"]
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
output_frame = ttk.Frame(window, padding=(10, 5))
output_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)

output_text = tk.Text(output_frame, height=20, font=("Arial", 12), wrap="word")
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(output_frame, command=output_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
output_text.config(yscrollcommand=scrollbar.set)

output_text.bind("<Button-1>", on_click)

# Status bar
status_var = tk.StringVar()
status_var.set("Welcome to Packet Sniffer")

status_bar = ttk.Label(window, textvariable=status_var, relief=tk.SUNKEN, anchor='w')
status_bar.grid(row=3, column=0, columnspan=3, sticky="ew")
window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(0, weight=1)

# Event loop
window.mainloop()
