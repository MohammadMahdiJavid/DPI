class FlowStats():

    def __init__(self):
        # Initialize flow stats parameters
        self.sent_packets_count = 0
        self.recieved_packets_count = 0
        self.sent_bytes_count = 0
        self.recieved_bytes_count = 0
        self.flow_start_time = 0
        self.flow_last_time = 0

    def get_total_packets_count(self):
        """ Return totol number of flow packets

        Returns:
            int: total number of flow packets
        """
        return self.sent_packets_count + self.recieved_packets_count

    def get_total_bytes_count(self):
        """ Return total bytes of flow

        Returns:
            int: total bytes of flow
        """
        return self.sent_bytes_count + self.recieved_bytes_count

    def get_flow_duration_time(self):
        """ Return flow time duration

        Returns:
            float: flow time duration
        """
        return self.flow_last_time - self.flow_start_time

    def update_stats(self, packet):
        """ Update flow stats parameters

        Args:
            packet (Packet): application packet instance of Packet class
        """
        # Set flow end time to the current packet timestamp
        # Corner Case: we have only one packet in the flow
        self.flow_last_time = packet.packet_timestamp
        if self.get_total_packets_count() == 0:
            # Set flow start time to first packet timestamp
            self.flow_start_time = packet.packet_timestamp
        if packet.is_packet_from_client:
            # Check if packet is from client and update sent packets and bytes status
            self.sent_packets_count += 1
            self.sent_bytes_count += len(packet.packet_data)
        else:
            # Check if packet is from server and update recieved packets and bytes status
            self.recieved_packets_count += 1
            self.recieved_bytes_count += len(packet.packet_data)
