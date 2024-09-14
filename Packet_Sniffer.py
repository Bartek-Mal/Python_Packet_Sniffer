from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP 
import tkinter as tk
from threading import Thread

action = None
packet_number = 0

def sniffing_action():
    global action
    action = 'sniffing'

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
        output_text.insert(tk.END, "Please select an action.\n")

def packet_callback(packet):
    global packet_number
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_number += 1
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport 
        elif ICMP in packet:
            proto = "ICMP"
            sport = packet[ICMP].sport
            dport = packet[ICMP].dport 
        else:
            proto = "Other"
            sport = None
            dport = None 
            
        packet_info = f"#{packet_number}. Protocol: {proto} | Source: {ip_src}:{sport} -> Destination: {ip_dst}:{dport}\n"
        output_text.insert(tk.END, packet_info)
        output_text.yview(tk.END)
        # hexdump(packet)

def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False)

# GUI

# Main window
window = tk.Tk()
window.title("Python Packet Sniffer")
window.geometry("700x800")
window.configure(bg="blue")

# Left corner action options 
option_frame = tk.Frame(window, bg="blue")
option_frame.grid(row=0, column=0, columnspan=3, pady=10, padx=10, sticky="w")

options = ["Save", "Open", "Quit", "HexDump"]

choose_option = tk.StringVar()
choose_option.set("Options")
option_choice_box = tk.OptionMenu(option_frame, choose_option, *options)
option_choice_box.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# Buttons at the top-left
sniffing = tk.Button(window, text="Sniff", command=sniffing_action, font=("Arial", 12), bg="red", fg="blue")
sniffing.grid(row=0, column=0, padx=120, pady=10, sticky="w")

opt1 = tk.Button(window, text="Opt1", command=None, font=("Arial", 12), bg="red", fg="blue")
opt1.grid(row=0, column=0, padx=190, pady=10, sticky="w")

opt2 = tk.Button(window, text="Opt2", command=None, font=("Arial", 12), bg="red", fg="blue")
opt2.grid(row=0, column=0, padx=260, pady=10, sticky="w")

# Frame for label, dropdown menu, and button
frame = tk.Frame(window, bg="blue")
frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="nsew")

# Center the content in the frame
frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=1)
frame.grid_columnconfigure(1, weight=1)

# Interface label and dropdown menu
interface_label = tk.Label(frame, text="Choose your interface:", font=("Arial", 18), bg="blue", fg="red")
interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")

interfaces = ["eth0", "wlan0", "lo", "any", "bluetooth0"]

choose_interface = tk.StringVar()
choose_interface.set(interfaces[0])  # Set eth0 as default
interface_choice_box = tk.OptionMenu(frame, choose_interface, *interfaces)
interface_choice_box.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# OK button in the middle of the row
button = tk.Button(window, text="OK", command=interface_function, font=("Arial", 12), bg="red", fg="blue")
button.grid(row=2, column=0, columnspan=3, pady=10)

# Frame for Text widget and Scrollbar
text_frame = tk.Frame(window)
text_frame.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Scrollable text widget for displaying packets or information
output_text = tk.Text(text_frame, height=30, font=("Arial", 12), wrap="word")
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a vertical scrollbar to the text widget
scrollbar = tk.Scrollbar(text_frame, command=output_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Configure the text widget to work with the scrollbar
output_text.config(yscrollcommand=scrollbar.set)

# Configure grid row and column weights to make sure they expand
window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(0, weight=1)
window.grid_columnconfigure(1, weight=1)
window.grid_columnconfigure(2, weight=1)

# Event loop
window.mainloop()
