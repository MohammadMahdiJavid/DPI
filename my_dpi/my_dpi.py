import re
from my_dpi.module.dns import Dns
from my_dpi.module.ntp import Ntp


class MyDpi:

    def __init__(self):
        self.udp_first_packet_patterns_callback_dict = {}
        self.tcp_first_packet_patterns_callback_dict = {}
        # Add new modules to this list
        self.protocols_list = [
            Dns,
            Ntp
        ]
        self.modules_objects = dict()
        for module_name in self.protocols_list:
            module_name(self)

    def register_udp_first_packet_callback(self, pattern, callback):
        """ Add pattern and its corresponding callback to UDP dictionary

        Args:
            pattern (byte raw string): regular expression pattern
            callback (function): callback function
        """
        self.udp_first_packet_patterns_callback_dict[pattern] = callback

    def register_tcp_first_packet_callback(self, pattern, callback):
        """ Add pattern and its corresponding callback to TCP dictionary

        Args:
            pattern (byte raw string): regular expression pattern
            callback (function): callback function
        """
        self.tcp_first_packet_patterns_callback_dict[pattern] = callback

    def feed_udp_first_packet(self, flow, application_packet):
        """ Match registered pattern with UDP application packet data
            then call the corresponding callback function if pattern is matched

        Args:
            flow (Flow): flow
            application_packet (Packet): application layer packet
        """
        for pattern in self.udp_first_packet_patterns_callback_dict:
            # Match (using re library) every regex pattern in udp_first_packet_patterns_callback_dict
            # keys with application_packet.packet_data, if it matched call the callback function
            # that previously registered in udp_first_packet_patterns_callback_dict
            ...

    def feed_tcp_first_packet(self, flow, application_packet):
        """ Match registered pattern with TCP application packet data
            then call the corresponding callback function if pattern is matched

        Args:
            flow (Flow): flow
            application_packet (Packet): application layer packet
        """
        for pattern in self.tcp_first_packet_patterns_callback_dict:
            # Similar to feed_udp_first_packet
            ...

    def inspect_packet(self, five_tuple_key, flow, application_packet):
        """ Inspection logic of the DPI

        Args:
            five_tuple_key (tuple): 5-tuple of the flow
            flow (Flow): flow
            application_packet (Pakcet): application layer packet
        """
        # Only inspect first packet
        if flow.get_total_packets_count() > 1:
            return

        # Feed TCP first packet
        if five_tuple_key[2]:
            self.feed_tcp_first_packet(
                flow,
                application_packet,
            )
        else:
            # feed UDP first packet
            self.feed_udp_first_packet(
                flow,
                application_packet,
            )
