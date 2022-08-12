class Ntp:
    def __init__(self, my_dpi):
        self.ntp_label = 'NTP'
        my_dpi.register_udp_first_packet_callback(
            br'^.{12}\x00{4}',
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        flow_dst_port = flow.get_five_tuple()[4]
        expected_dst_port = 123
        if (application_packet.packet_data[0] & 56 >> 3) < 4:
            if flow_dst_port == expected_dst_port:
                flow.set_protocol(self.ntp_label)
