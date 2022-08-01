import sys
import os
import dpkt
import datetime
import socket
import itertools
from DPI import settings


class Packet():
    def __init__(self, src_ip, src_port, dst_ip, dst_port, segment_type, timestamp, ethernet,
                 buffer, payload_size, flags, app_data):
        '''
        src_ip: Source IP Address
        src_port: Source Port number
        dst_ip: Destination IP Address
        dst_port: Destination Port number
        segment_type: Connection or Stream is TCP or UDP: transport layer protocol
        Frame Number shows the order of the packets
        timestamp: Time when the packet is captured
        ethernet: Ethernet of the frame
        buffer: Buffer of the frame
        payload_size: Size of the payload: len(payload) or len(protocol.data)
        flags: Flags of the frame if it doesn't contain only SYN, AKC
        app_data: application layer data of the frame
        app_protocol: application layer protocol of the frame
        '''
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.segment_type = segment_type
        self.timestamp = timestamp
        self.ethernet = ethernet
        self.app_data = app_data
        self.__five_tuple = frozenset((self.src_ip,
                                       self.src_port,
                                       self.dst_ip,
                                       self.dst_port,
                                       self.segment_type,)
                                      )
        self.buffer = buffer
        self.payload_size = payload_size
        self.flags = flags
        self.app_protocol = "UNKNOWN"

    def __eq__(self, __o: object):
        return self.buffer == __o.buffer

    @classmethod
    def parse_TCP(cls, protocol):
        # convert the flags to a string:‌ 2 --> SYN
        flags = dpkt.tcp.tcp_flags_to_str(protocol.flags)
        flags = set(flags.split(','))  # ['SYN', 'ACK']
        return flags

    @classmethod
    def extract_create_packet(cls, timestamp, buffer):
        '''
        extract information and create a packet from the buffer
        '''
        # ethernet frame, source ip, destination ip, segment: ICMP, UDP, TCP: transport layer data
        ethernet, src_ip, dst_ip, ip_payload, ip = cls.parse_base(buffer)
        flags = None
        payload_size = None
        # has data attribute and data payload is not empty
        has_payload = hasattr(ip_payload, 'data') and bool(ip_payload.data)
        if isinstance(ip_payload, dpkt.icmp.ICMP):
            # get the payload of ICMP
            ip_payload = cls.parse_ICMP(ip_payload)
            return  # drop ICMP packets
        elif isinstance(ip_payload, dpkt.tcp.TCP):
            if not has_payload:
                return  # return None if the packet doesn't have payload
            flags = cls.parse_TCP(ip_payload)
        src_port = ip_payload.sport  # source port
        dst_port = ip_payload.dport  # destination port
        segment_type = ip_payload.__class__.__name__
        if has_payload:
            # if it has payload what is it's size (in bytes)
            payload_size = len(ip_payload.data)
        return cls(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
                   segment_type=segment_type, timestamp=timestamp, ethernet=ethernet,
                   buffer=buffer, payload_size=payload_size, flags=flags, app_data=ip_payload.data)

    @classmethod
    def parse_ICMP(cls, protocol):
        protocol = protocol.data.data.udp
        return protocol

    @classmethod
    def parse_base(cls, buf):
        '''
        parse basic info that every packet has
        eth: Ethernet of the Frame
        ip: ip packet of the Ethernet
        src: Source IP Address
        dst: Destination IP Address
        ip_payload: segment data/payload of the ip packet: transport layer protocol
        '''
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        ethernet = dpkt.ethernet.Ethernet(buf)
        ip = ethernet.data  # Network Layer data
        src_ip = socket.inet_ntoa(ip.src) # source ip
        dst_ip = socket.inet_ntoa(ip.dst) # destination ip
        ip_payload = ip.data  # transport layer data
        return ethernet, src_ip, dst_ip, ip_payload, ip

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __str__(self):
        return f'{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} over {self.type}'

    def __repr__(self):
        return self.__str__()
