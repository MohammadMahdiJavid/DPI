import sys
import os
import dpkt
import datetime
import socket
import itertools


class Packet():
    def __init__(self, src, srcp, dst, dstp, protocol_type, timestamp, eth):
        '''
        src: Source IP Address
        srcp: Source Port number
        dst: Destination IP Address
        dstp: Destination Port number
        type: Connection or Stream is TCP or UDP
        Frame Number shows the order of the packets
        timestamp: Time when the packet is captured
        ethernet: Ethernet of the frame
        '''
        self.src = src
        self.srcp = srcp
        self.dst = dst
        self.dstp = dstp
        self.type = protocol_type
        self.timestamp = timestamp
        self.ethernet = eth
        self.protocol = "UNKNOWN"
        self.__five_tuple = frozenset((self.src,
                                       self.srcp,
                                       self.dst,
                                       self.dstp,
                                       self.type,)
                                      )

    def __eq__(self, __o: object):
        return self.five_tuple == __o.five_tuple and \
            self.timestamp == __o.timestamp

    @classmethod
    def extract_create_packet(cls, timestamp, buf):
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        protocol = ip.data
        srcp = protocol.sport
        dstp = protocol.dport
        protocol_type = protocol.__class__.__name__
        return cls(src=src, srcp=srcp, dst=dst, dstp=dstp, protocol_type=protocol_type, timestamp=timestamp, eth=eth)

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __str__(self):
        return f'{self.src}:{self.srcp} -> {self.dst}:{self.dstp} over {self.type}'

    def __repr__(self):
        return self.__str__()
