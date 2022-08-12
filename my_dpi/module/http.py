class Http:
    def __init__(self, my_dpi):
        self.http_label = 'HTTP'
        my_dpi.register_tcp_first_packet_callback(
            rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE) .{0,5000}HTTP\/1\.(0|1)(|\x0d)\x0a',
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.http_label)
