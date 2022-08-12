class Packet():

    def __init__(self, is_packet_from_client, packet_timestamp, packet_data):
        self.is_packet_from_client = is_packet_from_client
        self.packet_timestamp = packet_timestamp
        self.packet_data = packet_data
