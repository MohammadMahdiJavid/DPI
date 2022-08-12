import os
import sys
from my_dpi.my_dpi import MyDpi
from worker import Worker
import argparse


def get_arguments(args):
    """Get argument from user and parse them

    Args:
        args (_type_): _description_

    Returns:
        _type_: _description_
    """

    # Expect somthing like this: python3 main.py -r pcap_file.pcap
    parser = argparse.ArgumentParser(
        description="DPI is a program that can be used to analyze packet streams.\n\r"
        "use -h or --help to see the help", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-r', '--read', type=str, required=True, help='read a pcap file', dest='read_file', metavar='File Path')
    args = parser.parse_args()
    args.read_file = os.path.join('packets', args.read_file)
    return args


if __name__ == "__main__":
    my_dpi = MyDpi()
    dpi_worker = Worker(my_dpi)
    args = get_arguments(sys.argv[1:])
    dpi_worker.executor(os.path.abspath(args.read_file))
    dpi_worker.print_conversation()
