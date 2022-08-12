import socket
from my_dpi.flow_stats import FlowStats
from my_dpi.five_tuple import FiveTuple
from my_dpi.detection_state import DetectionState
import ipaddress
import datetime


class Flow(FlowStats, FiveTuple, DetectionState):

    def __init__(self, five_tuple):
        FlowStats.__init__(self)
        FiveTuple.__init__(self, five_tuple)
        DetectionState.__init__(self)

    # index used to count flow number
    index = -1

    def get_state_string(self):
        """ Get flow state string

        Returns:
            string: change flow state information to string
        """
        # convert binary format of ip address to string
        src_ip_str = socket.inet_ntoa(self.src_ip)
        # convert binary format of ip address to string
        dst_ip_str = socket.inet_ntoa(self.dst_ip)
        # if payload type is True, then it is TCP, otherwise it is UDP
        payload_type = 'TCP' if self.payload_type else 'UDP'
        # five tuple consists of source ip address, destination ip address, source port, destination port, protocol
        # five tuple is used to identify flow
        five_tuple = (src_ip_str, dst_ip_str, payload_type,
                      *self.get_five_tuple()[3:])
        # index used to count flow number
        Flow.index += 1
        return (f'### flow number {Flow.index}' +
                ' ' * 3 +
                f'### five tuple: {five_tuple}' +
                '\n'
                f'{src_ip_str}, {self.src_port} --> '
                f'{dst_ip_str}, {self.dst_port}: '
                f'{payload_type}: {self.protocol}; '
                f'sent packets: {self.sent_packets_count}, received packets: {self.recieved_packets_count}, '
                f'sent bytes: {self.sent_bytes_count}, received bytes: {self.recieved_bytes_count}, '
                f'timestamp: ({datetime.datetime.fromtimestamp(self.flow_start_time)}, '
                f'{datetime.datetime.fromtimestamp(self.flow_last_time)})' +
                f'\n' * 2
                )
