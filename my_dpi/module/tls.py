class Tls:
    def __init__(self, my_dpi):
        self.tls_label = 'TLS'
        my_dpi.register_tcp_first_packet_callback(
            rb'^\x16\x03[\x00-\x03].{2}\x01',
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.tls_label)
