class DetectionState():

    def __init__(self):
        unknown_label = "UNKNOWN"
        self.protocol = unknown_label

    def set_protocol(self, protocol_label):
        """ Set protocl label to flow

        Args:
            protocol_label (string): protocol label
        """
        self.protocol = protocol_label
