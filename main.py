#!.\dpi_env\Scripts\Activate.ps1 && python main.py -r example.pcap
import sys
import os
import dpkt
import datetime
import socket
import itertools


def parse_tcp(ip):
    '''
    parse the tcp packet
    '''
    # Make sure the IP data contains a TCP packet
    if not isinstance(ip.data, dpkt.tcp.TCP):
        print('Non TCP Packet type not supported %s\n' %
              ip.data.__class__.__name__)
        return False, None  # this packet contains no TCP data

    # Now access the data within the IP packet (the TCP packet)
    # Pulling out the TCP src and dst ports
    tcp = ip.data

    # Now see if we can parse the contents as a HTTP request
    try:
        request = dpkt.http.Request(tcp.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return False, None  # this packet contains no HTTP data

    print('HTTP request: %s\n' % repr(request))

    # Pretty print the TCP packet
    tcp.pprint()

    return True, tcp


def parse_icmp(ip):
    '''
    parse the icmp packet
    '''
    # Make sure the IP data contains an ICMP packet
    if not isinstance(ip.data, dpkt.icmp.ICMP):
        print('Non ICMP Packet type not supported %s\n' %
              ip.data.__class__.__name__)
        return False, None  # this packet contains no ICMP data

    # Now access the data within the IP packet (the ICMP packet)
    # Pulling out the ICMP type and code
    icmp = ip.data

    # Print out the ICMP type and code
    print('ICMP: type=%d code=%d' % (icmp.type, icmp.code))

    # Print out the info
    print('ICMP: type:%d code:%d checksum:%d data: %s\n' %
          (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))

    # Pretty print the ICMP packet
    icmp.pprint()


def parse_ip(eth):
    '''
    parse ethernet packet and return the ip packet
    if it has ip packet return True and ip packet
    if it doesn't have ip packet return False and None
    print out the ip packet information
    '''
    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' %
              eth.data.__class__.__name__)
        return False, None  # this packet contains no IP data

    # Now access the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Print out the info, including the fragment flags and offset
    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
          (dpkt.utils.inet_to_str(ip.src), dpkt.utils.inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))
    # read the source IP in src
    # converts a 32-bit packed IPv4 address to a string
    # b'\x8e\x84\xe7d'
    src = socket.inet_ntoa(ip.src)
    print(f'Source IP: {ip.src} : {src}')
    # read the destination IP in dst
    dst = socket.inet_ntoa(ip.dst)
    print(f'Destination IP: {ip.dst} : {dst}')

    # Pretty print the IP Packet
    ip.pprint()

    return True, ip  # this packet contains IP data


def parse_packets(pcap):
    '''
    Print out information about each packet in a pcap
    Args:
        pcap: dpkt pcap reader object(dpkt.pcap.Reader)
    '''
    # iterate through each packet in the pcap file
    for timestamp, buf in itertools.islice(pcap, 1):  # timestamp, buffer
        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', dpkt.utils.mac_to_str(
            eth.src), dpkt.utils.mac_to_str(eth.dst), eth.type)

        # Pretty print the Ethernet frame
        print('** Pretty print demo **\n')
        eth.pprint()

        has_ip, ip = parse_ip(eth)
        if not has_ip:  # if it doesn't have IP Packet continue to the next packet
            continue
        # if it has IP packet go for ICMP
        has_icmp, icmp = parse_icmp(ip)
        has_tcp, tcp = parse_tcp(ip)

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
              (dpkt.utils.inet_to_str(ip.src), dpkt.utils.inet_to_str(ip.dst), ip.len,
               ip.ttl, do_not_fragment, more_fragments, fragment_offset))


def get_file_path():
    '''
        return the file path
        are packets are stored in packets directory
        example:
        python main.py - r example.pcap
        it returns the example.pcap file path from packets directory
    '''
    default_file = None
    # default_file = r'./packets/randpkt-2016-10-02-27241.pcap'
    # default_file = r'./packets/my_capture_1.pcap'
    # default_file = r'./packets/my_capture_4.pcap'
    # default_file = r'./packets/randpkt-2020-09-06-16170.pcap'
    # default_file = r'./packets/MyCaptureDumpcap.pcap'
    file_path = default_file
    if '-r' in sys.argv:
        in_packets_dir = os.path.join('packets', sys.argv[-1])
        # if the file is in the current directory
        if os.path.exists(sys.argv[-1]):
            file_path = sys.argv[-1]
        # if the file is in the packets directory
        elif os.path.exists(in_packets_dir):
            file_path = in_packets_dir
        else:
            print("the file is not in the current directory or packets directory")
    return file_path


def main():
    sys.argc = len(sys.argv)
    file_path = get_file_path()
    # open pcap file for reading
    with open(file_path, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        parse_packets(pcap)


if __name__ == '__main__':
    main()
