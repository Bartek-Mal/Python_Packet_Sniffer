info = """ 
  Packet Sniffer - User Guide

    Overview:
    This application captures and displays network packets, allowing you to monitor traffic, apply filters, and view detailed information for each packet.

    Getting Started:
    - Choose Interface: Select the network interface (e.g., eth0, wlan0, etc.) for packet capture.
    - Start Sniffing: Click "Start Sniffing" to begin monitoring traffic on the chosen interface.
    - Stop Sniffing: Use "Stop Sniffing" to end the packet capture.

    File Menu:
    - Save: Saves the packet hexdumps to a file.
    - Open: Placeholder option (for future development).
    - Import from Hexdump: Opens a window to import and interpret a packet hexdump.
    - Quit: Closes the application.

    Using Filters:

    The filter section allows you to refine your packet search by criteria such as IP addresses, ports, or MAC addresses. This can be especially useful for isolating specific traffic within a large dataset.

    Filter Types and Syntax:
    - IP Filter: Use to filter packets based on the source or destination IP.
    - Port Filter: Use to narrow down packets by source or destination port.
    - MAC Filter: Use for filtering based on source or destination MAC address.

    Basic Filter Entry: Enter a single IP, port, or MAC in the filter box to search for packets matching that entry.

    Using '>' for Specific Filtering:
    You can use '>' to specify directionality, with the format '<source> > <destination>' for IPs, ports, and MACs. 
    If you only enter '> <destination>', it filters packets going to the specified destination, it works the same for source.
    This works with IP, Port, and MAC filters.

    Examples:
    - IP Filter: '192.168.1.10 > 192.168.1.20'
      - Displays packets with a source IP of 192.168.1.10 and a destination IP of 192.168.1.20.
    - IP Destination Only: '> 192.168.1.20'
      - Shows packets going to IP 192.168.1.20 from any source.
    - IP Source Only: '192.168.1.20 >'
      - Shows packets going to IP 192.168.1.20 from any source.
    - Port Filter: '80 > 8080'
      - Shows packets where the source port is 80 (typically HTTP) and the destination port is 8080.
    - MAC Filter: '00:11:22:33:44:55 > 66:77:88:99:AA:BB'
      - Filters packets sent from MAC address 00:11:22:33:44:55 to MAC address 66:77:88:99:AA:BB.

    Protocol Filters:
    - Use the "Filter" menu to toggle filters for protocols (e.g., TCP, UDP, ICMP). This narrows down the packets shown in combination with the IP/Port/MAC filters.

    Viewing Packets:
    - Captured packets are displayed in a list with columns like Protocol, Source/Destination, and Length. Click on any packet to view its details and hexdump.

    """