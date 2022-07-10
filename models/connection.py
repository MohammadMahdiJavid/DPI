class Connection():
    connections = {}

    def __init__(self):
        self.__packets = []
        self.__five_tuple = None

    @property
    def packets(self):
        return self.__packets.copy()

    def add_packet(self, packet):
        if packet in self.__packets:  # don't add if it's already in the list
            print('Packet already in connection')
            return
        if not self.__packets:  # if packets' list is empty
            self.__packets.append(packet)
            self.__five_tuple = packet.five_tuple
        # if the five tuple is the same and the packet is not in the list and the list is not empty
        elif self.__five_tuple == packet.five_tuple:
            self.__packets.append(packet)
        else:
            print("Error: Five tuple is not the same")

    def __eq__(self, __o: object):
        return self.__packets == __o.packets

    def __hash__(self):
        return hash(tuple(self.__packets))
