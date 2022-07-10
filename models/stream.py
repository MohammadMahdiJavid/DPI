class Stream():
    streams = {}
    count = 0

    def __init__(self, packet=None):
        self.__packets = [] if packet is None else [packet]
        self.__five_tuple = None if packet is None else packet.five_tuple
        Stream.streams[self.__five_tuple] = self
        self.index = Stream.count
        Stream.count = Stream.count + 1

    @property
    def packets(self):
        return self.__packets.copy()

    def add_packet_to_stream(self, packet):
        '''
        Add a packet to the Stream
        '''
        if packet in self.__packets:  # don't add if it's already in the list
            print('Packet already in Stream')
            return
        # if this is the first packet added set the five tuple for Stream
        if not self.__five_tuple and not self.__packets:
            raise Exception("Constructor didn't get a packet")
            self.__five_tuple = packet.five_tuple
            self.__packets.append(packet)
        # if the five tuple is the same and the packet is not in the list and the list is not empty
        elif self.__five_tuple == packet.five_tuple:
            self.__packets.append(packet)
        # if the five tuple is not the same and the list is not empty why add the packet?
        else:
            raise Exception("Error: Five tuple is not the same")

    @classmethod
    def add_packet(cls, packet):
        '''
        create a Stream if it doesn't exist and add the packet to it
        '''
        if packet.five_tuple not in cls.streams:
            stream = cls(packet=packet)
        else:
            stream = cls.streams[packet.five_tuple]
        stream.add_packet_to_stream(packet)

    @property
    def five_tuple(self):
        return self.__five_tuple

    def __eq__(self, __o: object):
        return type(self) == type(__o) and \
            self.__five_tuple == __o.five_tuple

    def __hash__(self):
        return hash(self.__five_tuple)
