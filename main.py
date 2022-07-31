#!..\dpi_env\Scripts\activate && python main.py -r example.pcap

'''
Entry file for the DPI program
'''

from DPI.models.dpi import DPI


def main():
    # create DPI object and parse the packets
    with DPI() as dpi:
        dpi.parse_packets()
        dpi.pprint()


if __name__ == '__main__':
    main()
