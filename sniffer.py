from scapy.all import sniff

def start_sniffing(interface, stop_sniff_event, packet_callback):
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
        stop_filter=lambda p: stop_sniff_event.is_set()
    )
