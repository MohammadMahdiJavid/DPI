import argparse
import os
from DPI.models.packet import Packet
from DPI.models.stream import Stream
import dpkt


class DPI ():
    '''
    DPI Object is used to parse and analyze packets
    it reads the pcap file path from console arguments
    for help use -h or --help
    '''

    def __init__(self):
        '''
        '''
        self.__init_parser()  # initialize argument parser for the DPI object
        self.__file = self.get_file_path()  # get file path from the argument parser

    def __init_parser(self):
        self.parser = argparse.ArgumentParser(
            description="DPI is a program that can be used to analyze packet streams.\n\r"
            "use -h or --help to see the help", formatter_class=argparse.RawTextHelpFormatter)
        self.parser.add_argument(
            '-r', '--read', type=str, required=True, help='read a pcap file', dest='file', metavar='File Path')
        self.args = self.parser.parse_args()

    def get_file_path(self):
        '''
        return the file path
        pcap files are stored in packets directory in the root of the project
        if it doesn't find the pcap file in the packets directory, it will look in the root of the project
        example:
            python main.py - r example.pcap
            it returns the example.pcap file path from packets directory
        '''
        file_path = self.args.file
        # file path in the packets directory
        in_packets_dir = os.path.join('packets', file_path)
        if os.path.exists(in_packets_dir):  # if the file is in the packets directory
            file_path = in_packets_dir
        elif os.path.exists(file_path):  # if the file is in the root of the project
            file_path = file_path
        else:
            raise Exception(
                "the file is not in the packets directory or the root of the project")
        return file_path

    def parse_packets(self):
        '''
        parse pcap file and create packets and streams
        '''
        # iterate through each packet in the pcap file
        for timestamp, buf in self.pcap:  # timestamp, buffer
            packet = Packet.extract_create_packet(
                timestamp, buf)  # create packet
            Stream.add_packet(packet)  # add packet to the correct stream

    def __enter__(self):
        '''
        read the pcap file with pcap reader
        file is provided by the argument parser in the __init__ function: --read option
        '''
        self.pcap_file = open(self.__file, 'rb')
        self.pcap = dpkt.pcap.Reader(self.pcap_file)  # create a pcap reader
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        '''
        close the pcap file
        '''
        self.pcap_file.close()

    def pprint(self):
        '''
        pretty print for the DPI Object
        '''
        print(f'DPI used {self.__file} as the pcap file')
        Stream.pprint()  # print the streams
