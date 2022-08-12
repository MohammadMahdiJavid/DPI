from my_dpi.flow_stats import FlowStats
from my_dpi.five_tuple import FiveTuple
from my_dpi.detection_state import DetectionState
import ipaddress
from datetime import datetime


class Flow(FlowStats, FiveTuple, DetectionState):

    def __init__(self, five_tuple):
        FlowStats.__init__(self)
        FiveTuple.__init__(self, five_tuple)
        DetectionState.__init__(self)

    def get_state_string(self):
        """ Get flow state string

        Returns:
            string: change flow state information to string
        """

        return ...
