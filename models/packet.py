import sys
import os
import dpkt
import datetime
import socket
import itertools


class Packet():
    def __init__(self, src, srcp, dst, dstp, protocol_type, timestamp, eth,
                 buf, payload_size, flags):
        '''
        src: Source IP Address
        srcp: Source Port number
        dst: Destination IP Address
        dstp: Destination Port number
        type: Connection or Stream is TCP or UDP
        Frame Number shows the order of the packets
        timestamp: Time when the packet is captured
        ethernet: Ethernet of the frame
        buffer: Buffer of the frame
        payload_size: Size of the payload: len(payload) or len(protocol.data)
        flags: Flags of the frame if it doesn't contain only SYN, AKC
        '''
        self.src_ip = src
        self.srcp = srcp
        self.dst_ip = dst
        self.dstp = dstp
        self.type = protocol_type
        self.timestamp = timestamp
        self.ethernet = eth
        self.protocol = "UNKNOWN"
        self.__five_tuple = frozenset((self.src_ip,
                                       self.srcp,
                                       self.dst_ip,
                                       self.dstp,
                                       self.type,)
                                      )
        self.buffer = buf
        self.payload_size = payload_size
        self.flags = flags

    def __eq__(self, __o: object):
        return self.buffer == __o.buffer

    @classmethod
    def extract_create_packet(cls, timestamp, buf):
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        protocol = ip.data
        flags = None
        payload_size = None
        if isinstance(protocol, dpkt.icmp.ICMP):
            protocol = protocol.data.data.udp
        elif isinstance(protocol, dpkt.tcp.TCP):
            # convert the flags to a string, 2 --> SYN
            flags = dpkt.tcp.tcp_flags_to_str(protocol.flags)
            # ['SYN', 'ACK']
            flags = set(flags.split(','))
            # don't add packets with only SYN and ACK flags
            if not flags.difference({'SYN', 'ACK'}):
                return  # return None if the packet is only SYN and ACK
        if hasattr(protocol, 'data'):
            # if it has payloard what is it's size
            payload_size = len(protocol.data)
        srcp = protocol.sport
        dstp = protocol.dport
        protocol_type = protocol.__class__.__name__
        if src == '10.42.0.196' and dst == '142.250.185.46' or \
                dst == '10.42.0.196' and src == '142.250.185.46':
            len(protocol.data)
            dpkt.tcp.TCP
        return cls(src=src, srcp=srcp, dst=dst, dstp=dstp,
                   protocol_type=protocol_type, timestamp=timestamp, eth=eth,
                   buf=buf, payload_size=payload_size, flags=flags)

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __str__(self):
        return f'{self.src_ip}:{self.srcp} -> {self.dst_ip}:{self.dstp} over {self.type}'

    def __repr__(self):
        return self.__str__()