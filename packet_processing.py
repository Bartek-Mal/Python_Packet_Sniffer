def packet_callback(packet, app):
    app.packet_queue.put(packet)
