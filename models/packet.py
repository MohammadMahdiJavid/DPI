class Packet():
    def __init__(self, src, srcp, dst, dstp, type):
        '''
        src: Source IP Address
        srcp: Source Port number
        dst: Destination IP Address
        dstp: Destination Port number
        type: Connection is TCP or UDP
        Frame Number shows the order of the packets
        '''
        self.src = src
        self.srcp = srcp
        self.dst = dst
        self.dstp = dstp
        self.type = type

    def __eq__(self, __o: object):
        pass

    @classmethod
    def extract_create_packet(cls, buf):
        pass

    @property
    def five_tuple(self):
        return set(self.src, self.srcp, self.dst, self.dstp, self.type)

    def __str__(self):
        return f'{self.src}:{self.srcp} -> {self.dst}:{self.dstp} over {self.type}'

    def __repr__(self):
        return self.__str__()
