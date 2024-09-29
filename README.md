# Python Packet Sniffer

Python Packet Sniffer is a graphical network packet sniffing tool built using Python's Tkinter GUI library and Scapy for packet capturing and manipulation. It allows you to capture and analyze network packets in real-time with a user-friendly interface.

## Features

- Real-time packet capturing on selected network interfaces.
- Filtering options for protocols: **TCP**, **UDP**, **ICMP**, **ARP**, and **DNS**.
- Ability to filter packets based on **IP addresses**, **ports**, or **MAC addresses**.
- Packet details and hexdump view.
- Import packets from hexdump.
- Save and open packet captures (functionality placeholders).

## Prerequisites

- **Python 3.x**
- **Tkinter** (usually included with Python installations)
- **Scapy**
- Necessary permissions to capture network packets (may require root/admin privileges)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Bartek-Mal/Python_Packet_Sniffer.git
   cd Python_Packet_Sniffer
   ```

2. **Install the required Python packages:**

   For Ubuntu/Debian:

   ```bash
   pip install scapy
   sudo apt-get install python3-tk
   ```

   For Fedora:

   ```bash
   pip install scapy
   sudo dnf install python3-tkinter
   ```

## Usage

Run the application:

```bash
sudo python3 main.py
```

Note: Root or administrator privileges may be required to capture network packets.

### Using the GUI:

1. **Select Interface:** Choose the network interface you want to sniff on from the dropdown menu.
2. **Set Filters (Optional):** You can filter packets by IP, Port, or MAC addresses using the filter options.
3. **Protocol Filters:** Use the "Filter" menu to select which protocols to capture (TCP, UDP, ICMP, ARP, DNS).
4. **Start Sniffing:** Click the "Start Sniffing" button to begin capturing packets.
5. **Stop Sniffing:** Click the "Stop Sniffing" button to stop capturing packets.
6. **View Packet Details:** Click on a packet in the list to view its detailed information and hexdump.
7. **Import from Hexdump:** Use the "File" menu to import packets from a hexdump.
8. **Save/Open Captures:** Use the "File" menu to save or open packet captures (functionality placeholders).

## Notes

- **Permissions:** Capturing network packets may require elevated permissions. Ensure you have the necessary permissions to run the sniffer.
- **Interfaces:** The list of interfaces in the GUI is hardcoded (["any", "eth0", "wlan0", "lo", "bluetooth0"]). You may need to adjust the list to match your system's interfaces in the `gui.py` file.
- **Cross-Platform Compatibility:** The application has been tested on Linux systems. Compatibility with Windows and macOS is not guaranteed.
- **Dependencies:** Ensure all dependencies are installed correctly. Missing packages can lead to runtime errors.

## Troubleshooting

- **Permission Denied Error:** If you encounter permission issues, try running the application with `sudo`.
- **Interface Not Found:** If your network interface is not listed, you can manually add it to the list in the GUI or modify the code to automatically detect available interfaces.
- **No Packets Captured:** Ensure that the selected interface is active and that there is network traffic to capture.


