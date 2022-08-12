class Dns:
    def __init__(self, my_dpi):
        self.dns_label = 'DNS'
        my_dpi.register_udp_first_packet_callback(
            br'^.{4}\x00[\x01-\x0f]\x00.{5}',
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.dns_label)
