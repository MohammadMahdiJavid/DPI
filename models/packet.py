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

    debugger_counter = 1

    @classmethod
    def catch_debugger(cls, *args, **kwargs):
        # ips = ['10.42.0.196', '142.250.185.46']
        # ips = ['143.204.11.14', '10.42.0.184']
        ips = ['10.42.0.196', '10.42.0.1']
        ports = [31776, 53]
        # if kwargs['srcp'] == 31776 or kwargs['dstp'] == 31776:
        #     pass
        if kwargs['src'] in ips and kwargs['dst'] in ips and \
                kwargs['srcp'] in ports and kwargs['dstp'] in ports:
            print(f'frame {cls.debugger_counter}')
            cls.debugger_counter = cls.debugger_counter + 1

    @classmethod
    def parse_TCP(cls, protocol):
        # convert the flags to a string, 2 --> SYN
        flags = dpkt.tcp.tcp_flags_to_str(protocol.flags)
        # ['SYN', 'ACK']
        flags = set(flags.split(','))
        # don't add packets with only SYN flags
        # if not flags.difference({'SYN'}):
        #     return  # return None if the packet is only SYN
        # # has only ACK in the flags
        # if len(flags) == 1 and 'ACK' in flags \
        #    and not has_payload:  # ACK and payload is empty
        #     return  # return None if the packet is only ACK and it doesn't have payload
        return flags

    @classmethod
    def parse_UDP(cls):
        pass

    @classmethod
    def extract_create_packet(cls, timestamp, buf):
        # ethernet, source ip, destination ip, protocol: ICMP, UDP, TCP
        eth, src, dst, protocol, ip = cls.parse_base(buf)
        flags = None
        payload_size = None
        # has data attribute and not empty
        has_payload = hasattr(protocol, 'data') and bool(protocol.data)
        if isinstance(protocol, dpkt.icmp.ICMP):
            # get the payload of ICMP
            protocol = cls.parse_ICMP(protocol)
            return  # drop ICMP packets
        elif isinstance(protocol, dpkt.tcp.TCP):
            if not has_payload:
                return  # return None if the packet doesn't have payload
            flags = cls.parse_TCP(protocol)
        elif isinstance(protocol, dpkt.udp.UDP):
            cls.parse_UDP()
        srcp = protocol.sport
        dstp = protocol.dport
        protocol_type = protocol.__class__.__name__
        cls.catch_debugger(src=src, dst=dst, timestamp=timestamp,
                           eth=eth, srcp=srcp, dstp=dstp)
        if has_payload:
            # if it has payload what is it's size (in bytes)
            payload_size = len(protocol.data)
        return cls(src=src, srcp=srcp, dst=dst, dstp=dstp,
                   protocol_type=protocol_type, timestamp=timestamp, eth=eth,
                   buf=buf, payload_size=payload_size, flags=flags)

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
