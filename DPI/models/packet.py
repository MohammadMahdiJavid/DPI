import re
import sys
import os
import dpkt
import datetime
import socket
import itertools
from DPI import settings

if settings.DEBUG:
    from DPI.debug.debugger import Debugger


class Packet():
    patterns = {  # byte string object patterns to find out which protocol is used
        rb"^.{4}\x21\x12\xa4\x42": ('UDP', 'STUN'),
        rb'^\x16\x03[\x00-\x03].{2}\x01': ('TCP', 'TLS'),
        rb'^.{4}\x00[\x01-\x0f]\x00.{5}': ('UDP', 'DNS'),
        rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE) .{0,5000}HTTP\/1\.(0|1)(|\x0d)\x0a': ('TCP', 'HTTP'),
    }

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
        self.app_protocol = self.get_protocol()

    def __eq__(self, __o: object):
        return self.buffer == __o.buffer

    def get_protocol(self):
        '''
        parse the buffer and return the application layer protocol of the packet

        test:
            UDP, STUN --> udp.stream eq 12 --> 
            261	10.42.0.196	31.13.64.50	UDP	206	4-UDP	UDP	64	12  43539 → stun(3478) Len=164

        '''
        if settings.DEBUG:
            Debugger.catch_debugger(src=self.src_ip, dst=self.dst_ip)
        # regex pattern, transport layer protocol, application layer protocol
        for pattern, (segment_protocol, app_protocol) in self.__class__.patterns.items():
            if re.search(pattern, self.app_data):
                if segment_protocol != self.segment_type:
                    raise Exception(
                        f'{segment_protocol} != {self.segment_type}')
                return app_protocol
        return 'UNKNOWN'

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
        if not ip:
            return
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
    def parse_ICMP(cls, segment):
        app_data = segment.data.data.udp  # application layer protocol of ICMP
        return app_data

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
        if not isinstance(ip, dpkt.ip.IP):
            return None, None, None, None, None
        src_ip = socket.inet_ntoa(ip.src)  # source ip
        dst_ip = socket.inet_ntoa(ip.dst)  # destination ip
        ip_payload = ip.data  # transport layer data
        return ethernet, src_ip, dst_ip, ip_payload, ip

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __str__(self):
        return f'{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} over {self.type}'

    def __repr__(self):
        return self.__str__()
