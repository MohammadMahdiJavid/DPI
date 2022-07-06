#!./dpi_env/Scripts/python
import sys
import dpkt
import datetime


def parse_packets(pcap):
    '''
    Print out information about each packet in a pcap
    Args:
        pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    '''
    # iterate through each packet in the pcap file
    for timestamp, buf in pcap:
        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', dpkt.utils.mac_to_str(
            eth.src), dpkt.utils.mac_to_str(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' %
                  eth.data.__class__.__name__)
            continue

        # Now access the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Print out the info, including the fragment flags and offset
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
              (dpkt.utils.inet_to_str(ip.src), dpkt.utils.inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))

    # Pretty print the last packet
    print('** Pretty print demo **\n')
    eth.pprint()


def main():
    sys.argc = len(sys.argv)
    default_packet = r'./packets/randpkt-2016-10-02-27241.pcap'
    file_path = sys.argv[-1] if sys.argc < 3 else default_packet
    # open pcap file for reading
    with open(file_path, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        parse_packets(pcap)


if __name__ == '__main__':
    main()
