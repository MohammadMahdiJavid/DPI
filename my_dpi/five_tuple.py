class FiveTuple():

    def __init__(self, five_tuple):
        self.src_ip = five_tuple[0]
        self.dst_ip = five_tuple[1]
        self.payload_type = five_tuple[2]
        self.src_port = five_tuple[3]
        self.dst_port = five_tuple[4]

    def get_five_tuple(self):
        """ Get 5-tuple

        Returns:
            tuple: 5-tuple
        """
        return (self.src_ip, self.dst_ip, self.payload_type, self.src_port, self.dst_port)

    def get_reversed_five_tuple(self):
        """ reverse Get 5-tuple

        Returns:
            tuple: reverse 5-tuple
        """
        return (self.dst_ip, self.src_ip, self.payload_type, self.dst_port, self.src_port)

    @staticmethod
    def get_five_tuple_of_packet(ip_packet):
        """ Static method for getting 5-tuple and reverse 5-tuple from IP packet
            payload_type is True if layer 4 protocol is TCP, False otherwise
        Args:
            ip_packet (bytes): packet with IP header

        Returns:
            tuple, tuple: five_tuple and reversed_five_tuple
        """
        five_tuple = (
            ip_packet.src,
            ip_packet.dst,
            (ip_packet.p == 6),
            ip_packet.data.sport,
            ip_packet.data.dport
        )
        reversed_five_tuple = (
            ip_packet.dst,
            ip_packet.src,
            (ip_packet.p == 6),
            ip_packet.data.dport,
            ip_packet.data.sport
        )
        return five_tuple, reversed_five_tuple
