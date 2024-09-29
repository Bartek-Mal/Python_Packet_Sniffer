import tkinter as tk
from tkinter import ttk, messagebox
from scapy.utils import hexdump

def show_packet_info(packet_show_data, hexdump_data):
    packet_window = tk.Toplevel()
    packet_window.title("Packet Details and Hexdump")
    packet_window.geometry("800x600")

    # Packet Details
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

    # Scrollbars
    scrollbar1 = tk.Scrollbar(packet_window, command=packet_show_text.yview)
    scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
    packet_show_text.config(yscrollcommand=scrollbar1.set)

    scrollbar2 = tk.Scrollbar(packet_window, command=hexdump_text.yview)
    scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    hexdump_text.config(yscrollcommand=scrollbar2.set)

def import_from_hexdump(app):
    import_window = tk.Toplevel(app.window)
    import_window.title("Import from hexdump...")
    import_window.geometry("800x600")

    hexdump_insert_label = tk.Label(import_window, text="Hexdump:")
    hexdump_insert_label.pack()

    hexdump_text = tk.Text(import_window, height=15, font=("Courier", 10), wrap="none")
    hexdump_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(import_window, command=hexdump_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    hexdump_text.config(yscrollcommand=scrollbar.set)

    packet_info_label = tk.Label(import_window, text="Packet info:")
    packet_info_label.pack()

    packet_info_text = tk.Text(import_window, height=15, font=("Courier", 10), wrap="none")
    packet_info_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    scrollbar2 = tk.Scrollbar(import_window, command=packet_info_text.yview)
    scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    packet_info_text.config(yscrollcommand=scrollbar2.set)

    process_button = ttk.Button(
        import_window,
        text="Process Hexdump",
        command=lambda: hexdump_interpreter(hexdump_text.get("1.0", tk.END), packet_info_text, app)
    )
    process_button.pack(pady=10)

def hexdump_interpreter(hexdump_input, packet_info_text, app):
    hexdump_input = hexdump_input.strip()

    if hexdump_input in app.packet_hexdumps:
        hexdump_index = app.packet_hexdumps.index(hexdump_input)
        if hexdump_index < len(app.packets):
            packet = app.packets[hexdump_index]
            packet_show_data = packet.show(dump=True)
            packet_info_text.insert(tk.END, packet_show_data)
        else:
            messagebox.showerror("Error", "Hexdump out of bounds!")
    else:
        messagebox.showerror("Error", "Hexdump not found!")
