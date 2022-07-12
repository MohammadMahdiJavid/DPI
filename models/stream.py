import sys
import os
import dpkt
import datetime
import socket
import itertools


class Stream():
    streams = {}
    count = 0

    def __init__(self, packet=None):
        '''
        __packets: contains all packets in the stream
        __five_tuple: contains the five tuple of the stream which is five tuple of the first packet
        index: contains the index of the stream
        src_pkt: contains the first packet in the stream 
            --> can give us source and destination IP and timestamp
        sbytes: sent bytes of the stream: first packet payload size
        rbytes: received bytes of the stream
        spkts: sent packets of the stream
        rpkts: received packets of the stream
        '''
        if packet is None:
            raise Exception("Error: Stream constructor didn't get a packet")
        self.src_pkt = packet
        self.__packets = [packet]
        self.__five_tuple = packet.five_tuple
        Stream.streams[self.__five_tuple] = self
        self.index = Stream.count
        Stream.count = Stream.count + 1
        self.sbytes = packet.payload_size  # first packet is always sent
        self.rbytes = 0
        self.spkts = 1  # first packet is always sent
        self.rpkts = 0

    @property
    def packets(self):
        return self.__packets.copy()

    def add_packet_info(self, packet):
        '''
        add sbytes, rbytes, spkts, rpkts to the stream with comparing 
        the packet with the first packet in the stream
        '''
        if packet.src_ip == self.src_pkt.src_ip:
            self.sbytes += packet.payload_size
            self.spkts += 1
        elif packet.dst_ip == self.src_pkt.src_ip:
            self.rbytes += packet.payload_size
            self.rpkts += 1
        else:
            raise Exception(
                f'Error: source packet of the Stream is {self.src_pkt} and packet is {packet}'
            )

    def add_packet_to_stream(self, packet):
        '''
        Add a packet to the Stream
        '''
        if packet in self.__packets:  # don't add if it's already in the list
            print('Packet already in Stream')
            return
        # if this is the first packet added then set the five tuple for Stream
        if not self.__five_tuple and not self.__packets:
            raise Exception("Constructor didn't get a packet")
            self.__five_tuple = packet.five_tuple
            self.__packets.append(packet)
        # if the five tuple is the same and the packet is not in the list and the list is not empty
        elif self.__five_tuple == packet.five_tuple:
            self.__packets.append(packet)
            self.add_packet_info(packet)
        # if the five tuple is not the same and the list is not empty why add the packet?
        else:
            raise Exception("Error: Five tuple is not the same")

    @classmethod
    def add_packet(cls, packet):
        '''
        create a Stream if it doesn't exist and add the packet to it
        '''
        if packet is None:  # guard statement
            return
        # creates new stream if it doesn't exist
        # adds the packet to it when it's the first packet
        if packet.five_tuple not in cls.streams:
            stream = cls(packet=packet)
        else:  # stream exists
            stream = cls.streams[packet.five_tuple]
            stream.add_packet_to_stream(packet)  # add packet to the stream

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __eq__(self, __o: object):
        return type(self) == type(__o) and \
            self.__five_tuple == __o.five_tuple

    def __hash__(self):
        return hash(self.__five_tuple)

    @classmethod
    def pprint(cls):
        '''
        print the stream and their packet information pretty to the console
        save the packets' information in the output.txt file in outputs directory
        '''
        if not os.path.exists('outputs'):
            os.mkdir('outputs')
        with open('outputs/output.txt', 'w') as file:
            for five_tuple, stream in cls.streams.items():
                last_pkt = stream.packets[-1]
                output = (
                    f'### flow number {stream.index}' +
                    ' ' * 3 +
                    f'### five tuple: {",".join([str(item) for item in five_tuple])}'
                    '\n'
                    f'{stream.src_pkt.src_ip}, {stream.src_pkt.srcp} --> '
                    f'{stream.src_pkt.dst_ip}, {stream.src_pkt.dstp}: '
                    f'{stream.src_pkt.type}: {stream.src_pkt.protocol}; '
                    f'sent packets: {stream.spkts}, received packets: {stream.rpkts}, '
                    f'sent bytes: {stream.sbytes}, received bytes: {stream.rbytes}, '
                    f'timestamp: ({datetime.datetime.fromtimestamp(stream.src_pkt.timestamp)}, '
                    f'{datetime.datetime.fromtimestamp(last_pkt.timestamp)}) ' +
                    f'\n' * 2
                )
                print(output, end='')
                file.write(output)
