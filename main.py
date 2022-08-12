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
    return ...


if __name__ == "__main__":
    my_dpi = MyDpi()
    dpi_worker = Worker(my_dpi)
    args = get_arguments(sys.argv[1:])
    dpi_worker.executor(os.path.abspath(args.read_file))
    dpi_worker.print_conversation()
