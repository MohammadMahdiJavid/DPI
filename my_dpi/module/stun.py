class Stun:
    def __init__(self, my_dpi):
        self.stun_label = 'STUN'
        my_dpi.register_udp_first_packet_callback(
            rb"^.{4}\x21\x12\xa4\x42",
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.stun_label)
