import dpkt
from my_dpi.flow import Flow
from my_dpi.packet import Packet
from my_dpi.five_tuple import FiveTuple


class Worker:
    def __init__(self, my_bdpi):
        self.flows_dict = {}
        self.my_dpi = my_bdpi

    def process_packet(self, packet_payload, timestamp):
        """ Initial process for every packet and feed the valid packets to DPI

        Args:
            packet_payload (bytes): packet bytes
            timestamp (float): packet timestamp
        """
        # Check packet first layer protocol is Ethernet

        # Check packet second layer protocol is IP

        # Check packet third layer protocol is UDP or TCP

        # skip UDP/TCP zero length payload

        # extract 5-tuple of packet
        five_tuple_key, reversed_five_tuple_key = FiveTuple.get_five_tuple_of_packet(ip_packet)
        is_packet_from_client = True
        # check 5-tuple or its reverse order exist in flows_dict dictionary before
        if five_tuple_key in self.flows_dict:
            ...
        elif reversed_five_tuple_key in self.flows_dict:
            ...
        else:
            flow = Flow(five_tuple_key)

        # add packet data to dictionary
        application_data = ip_packet.data.data

        application_packet = Packet(is_packet_from_client, timestamp, application_data)
        flow.update_stats(application_packet)
        self.flows_dict.update({five_tuple_key: flow})
        self.my_dpi.inspect_packet(five_tuple_key, flow, application_packet)

    def print_conversation(self):
        """Print flows_dict conversation in terminal
        """
        for flow_key in self.flows_dict:
            # Get flow state string from get_state_string function and print it here
            ...

    def executor(self, pcap_file_name):
        """ Read every packet from pcap file

        Args:
            pcap_file_name (string): path of the pcap file
        """
        # open pcap file and feed every packet to process packet function
        ...