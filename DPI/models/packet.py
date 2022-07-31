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
    def __init__(self, src, srcp, dst, dstp, segment_type, timestamp, eth,
                 buf, payload_size, flags, app_data):
        '''
        src: Source IP Address
        srcp: Source Port number
        dst: Destination IP Address
        dstp: Destination Port number
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
        self.src_ip = src
        self.srcp = srcp
        self.dst_ip = dst
        self.dstp = dstp
        self.segment_type = segment_type
        self.timestamp = timestamp
        self.ethernet = eth
        self.app_data = app_data
        self.__five_tuple = frozenset((self.src_ip,
                                       self.srcp,
                                       self.dst_ip,
                                       self.dstp,
                                       self.segment_type,)
                                      )
        self.buffer = buf
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
    def parse_UDP(cls):
        pass

    @classmethod
    def extract_create_packet(cls, timestamp, buf):
        '''
        extract and create a packet from the buffer
        '''
        # ethernet frame, source ip, destination ip, segment: ICMP, UDP, TCP: transport layer data
        eth, src, dst, segment, ip = cls.parse_base(buf)
        flags = None
        payload_size = None
        # has data attribute and data payload is not empty
        has_payload = hasattr(segment, 'data') and bool(segment.data)
        if isinstance(segment, dpkt.icmp.ICMP):
            # get the payload of ICMP
            segment = cls.parse_ICMP(segment)
            return  # drop ICMP packets
        elif isinstance(segment, dpkt.tcp.TCP):
            if not has_payload:
                return  # return None if the packet doesn't have payload
            flags = cls.parse_TCP(segment)
        elif isinstance(segment, dpkt.udp.UDP):
            cls.parse_UDP()
        srcp = segment.sport
        dstp = segment.dport
        segment_type = segment.__class__.__name__
        if settings.DEBUG:  # if debugger is enabled catch this packet
            print(f'{src}:{srcp} -> {dst}:{dstp} over {segment_type}')
            Debugger.catch_debugger(src=src, dst=dst, timestamp=timestamp,
                                    eth=eth, srcp=srcp, dstp=dstp)
        if has_payload:
            # if it has payload what is it's size (in bytes)
            payload_size = len(segment.data)
        return cls(src=src, srcp=srcp, dst=dst, dstp=dstp,
                   segment_type=segment_type, timestamp=timestamp, eth=eth,
                   buf=buf, payload_size=payload_size, flags=flags, app_data=segment.data)

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
        protocol: Protocol of the ip packet
        '''
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        protocol = ip.data
        return eth, src, dst, protocol, ip

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __str__(self):
        return f'{self.src_ip}:{self.srcp} -> {self.dst_ip}:{self.dstp} over {self.type}'

    def __repr__(self):
        return self.__str__()
