from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk

action = None

def sniffing_action():
    global action
    action = 'sniffing'

def interface_function():
    interface_dropbox_choice = choose_interface.get()  # Get the selected interface
    if action:
        output_text.insert(tk.END, f"Selected interface: {interface_dropbox_choice}\n")
        output_text.insert(tk.END, f"Action: {action}\n")
    else:
        output_text.insert(tk.END, "Please select an action.\n")
        
        
#GUI

# Main window
window = tk.Tk()
window.title("Python Packet Sniffer")
window.geometry("700x800")
window.configure(bg="blue")

# Buttons at the top-left
sniffing = tk.Button(window, text="Sniff", command=sniffing_action, font=("Arial", 12), bg="red", fg="blue")
sniffing.grid(row=0, column=0, padx=10, pady=10, sticky="w")

opt1 = tk.Button(window, text="Opt1", command=None, font=("Arial", 12), bg="red", fg="blue")
opt1.grid(row=0, column=0, padx=110, pady=10, sticky="w")

opt2 = tk.Button(window, text="Opt2", command=None, font=("Arial", 12), bg="red", fg="blue")
opt2.grid(row=0, column=0, padx=210, pady=10, sticky="w")

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
button.grid(row=2, column=0, columnspan=2, pady=10)

# Frame for Text widget and Scrollbar
frame = tk.Frame(window)
frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

# Scrollable text widget for displaying packets or information
output_text = tk.Text(frame, height=30, font=("Arial", 12), wrap="word")
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a vertical scrollbar to the text widget
scrollbar = tk.Scrollbar(frame, command=output_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Configure the text widget to work with the scrollbar
output_text.config(yscrollcommand=scrollbar.set)

# Configure grid row and column weights to make sure they expand
window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(0, weight=1)
window.grid_columnconfigure(1, weight=1)

# Event loop
window.mainloop()
