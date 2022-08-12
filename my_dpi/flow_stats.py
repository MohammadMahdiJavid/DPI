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
            int: totol number of flow packets
        """
        return ...

    def get_total_bytes_count(self):
        """ Return total bytes of flow

        Returns:
            int: total bytes of flow
        """
        return ...

    def get_flow_duration_time(self):
        """ Return flow time duration

        Returns:
            float: flow time duration
        """
        return ...

    def update_stats(self, packet):
        """ Update flow stats parameters

        Args:
            packet (Packet): application packet instance of Packet class
        """
        if packet.is_packet_from_client:
            # Check if packet is from client and update sent packets and bytes status
            ...
        else:
            ...
