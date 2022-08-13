class Quic:
    ''' QUIC common header: long and short
    Long form packets are used for the initial exchange - 
    until both 1-RTT packet protection can be started AND 
    version negotiation is complete

    Short form packets carry the bulk of the data.

    Fields are aligned on four octet boundaries. 
    All long-form header variations have the exact same form.

    The connection ID is in the same place in both short and long form.

    The long form clearly identifies the role of the sender in the first octet 
    and it identifies the packet as a QUIC packet.

    long header is 20 octets, whereas the existing form uses between 14 and 19 
    octets for initial handshake packets

    Octet 0: Special
    Bit 7 (i.e., 0x80): SHORT_HEADER (set to 0 here)
    Bit 6-5: Type
    11 - client packet
    10 - server packet
    01 - public reset
    00 - version negotiation
    Bits 4-0: Next protocol
    0b10001 indicates that it is QUIC handshake data
    0b01111 indicates that it is QUIC 0-RTT data
    other values mean that the payload following the packet number contains an IPv6-style extension header

    Initial Packet {
       Header From (1) = 1,
       Fixed Big (1) = 1,
       Long Packet Type (2) = 0,
       Reserved Bits (2),
       Packet Number Length (2),
       Version (32),
       Destination Connection ID Length (8),
       Destination Connection ID (0..160),
       Source Connection ID Length (8),
       Source Connection ID (0..160),
       Token Length (i),
       Token (..),
       Encryption Context Length (8),
       Encryption Context (..),
       Length (i),
       Packet Number (8..32),
    }

    Encryption Context Length: 
    A variable-length integer specifying the length of the encryption context, in bytes. 
    Servers MUST set this field to zero; 
    a client that receives a non-zero length MUST either discard the packet or 
    generate a connection error of type PROTOCOL_VIOLATION.
    Clients MUST include a nonzero Encryption Context Length in all 
    Initial packets, unless executing fallback procedures
    When the client includes a non-zero-length Encryption Context, 
    it MUST include an initial_encryption_context in its Client Hello, 
    so that this header field is included in the TLS handshake transcript.

    Client:
    The endpoint initiating a QUIC connection.
    Server:
    The endpoint accepting incoming QUIC connections.

    All numeric values are encoded in network byte order (that is, big-endian)
    all field sizes are in bits
    least significant bit is referred to as bit 0

    Any QUIC packet has either a long or a short header, as indicated by the Header Form bit
    Long headers are expected to be used early in the connection before 
    version negotiation and establishment of 1-RTT keys. 
    Short headers are minimal version-specific headers, which are used after 
    version negotiation and 1-RTT keys are established.

    Long:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+
    |1|   Type (7)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                       Connection ID (64)                      +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Packet Number (32)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Version (32)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Payload (*)                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Header Form:
    The most significant bit (0x80) of octet 0 (the first octet) is set to 1 for long headers.

    Long Packet Type:
    The remaining seven bits of octet 0 contain the packet type. 
    This field can indicate one of 128 packet types. 
    The types specified for this version are listed in Table 1.

    Connection ID:
    Octets 1 through 8 contain the connection ID.

    Packet Number:
    Octets 9 to 12 contain the packet number.

    Version:
    Octets 13 to 16 contain the selected protocol version. 
    This field indicates which version of QUIC is in use and 
    determines how the rest of the protocol fields are interpreted.

    Payload:
    Octets from 17 onwards (the rest of QUIC packet) are the payload of the packet.

    Between different versions the following things are guaranteed to remain constant:
    the location of the header form flag,
    the location of the Connection ID flag in short headers,
    the location and size of the Connection ID field in both header forms,
    the location and size of the Version field in long headers,
    the location and size of the Packet Number field in long headers, and
    the type, format and semantics of the Version Negotiation packet.

    Long Header Packets

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+
       |1|1|T T|X X X X|
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Version (32)                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | DCID Len (8)  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |               Destination Connection ID (0..160)            ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | SCID Len (8)  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 Source Connection ID (0..160)               ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Figure 9: Long Header Packet Format

    Header Form:  The most significant bit (0x80) of byte 0 (the first
        byte) is set to 1 for long headers.

    Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
        containing a zero value for this bit are not valid packets in this
        version and MUST be discarded.

    Long Packet Type (T):  The next two bits (those with a mask of 0x30)
        of byte 0 contain a packet type.  Packet types are listed in
        Table 5.

    +------+-----------+----------------+
    | Type | Name      | Section        |
    +------+-----------+----------------+
    |  0x0 | Initial   | Section 17.2.2 |
    |      |           |                |
    |  0x1 | 0-RTT     | Section 17.2.3 |
    |      |           |                |
    |  0x2 | Handshake | Section 17.2.4 |
    |      |           |                |
    |  0x3 | Retry     | Section 17.2.5 |
    +------+-----------+----------------+

    Table 5: Long Header Packet Types

       Type-Specific Bits (X):  The lower four bits (those with a mask of
          0x0f) of byte 0 are type-specific.

       Version:  The QUIC Version is a 32-bit field that follows the first
          byte.  This field indicates which version of QUIC is in use and
          determines how the rest of the protocol fields are interpreted.

       DCID Len:  The byte following the version contains the length in
          bytes of the Destination Connection ID field that follows it.
          This length is encoded as an 8-bit unsigned integer.  In QUIC
          version 1, this value MUST NOT exceed 20.  Endpoints that receive
          a version 1 long header with a value larger than 20 MUST drop the
          packet.  Servers SHOULD be able to read longer connection IDs from
          other QUIC versions in order to properly form a version
          negotiation packet.

       Destination Connection ID:  The Destination Connection ID field
          follows the DCID Len and is between 0 and 20 bytes in length.
          Section 7.2 describes the use of this field in more detail.

       SCID Len:  The byte following the Destination Connection ID contains
          the length in bytes of the Source Connection ID field that follows
          it.  This length is encoded as a 8-bit unsigned integer.  In QUIC
          version 1, this value MUST NOT exceed 20 bytes.  Endpoints that
          receive a version 1 long header with a value larger than 20 MUST
          drop the packet.  Servers SHOULD be able to read longer connection
          IDs from other QUIC versions in order to properly form a version
          negotiation packet.

    Resources:
    1- https://www.ietf.org/id/draft-duke-quic-protected-initial-04.html
    2- https://greenbytes.de/tech/webdav/draft-ietf-quic-transport-07.xml
    3- https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-13
    4- https://github.com/quicwg
    5- https://quicwg.org/
    6- https://github.com/quicwg/base-drafts/wiki/Implementations
    7- https://quic.xargs.org/
    8- https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-23
    '''

    def __init__(self, my_dpi):
        self.quic_label = 'QUIC'
        my_dpi.register_udp_first_packet_callback(
            rb'^[\xc0-\xff]\x00{3}\x01',
            self.callback_function
        )

    def callback_function(self, flow, application_packet):
        application_packet_data = application_packet.packet_data
        '''
        The payload of a UDP datagram carrying the Initial packet MUST be
        expanded to at least 1200 octets (see Section 8), by adding PADDING
        frames to the Initial packet and/or by combining the Initial packet
        with a 0-RTT packet (see Section 4.6).
        https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-13#section-4.4.1.4
        '''
        if len(application_packet_data) < 1200:
            return
        # Long Header Check for first packet # Long: 1
        if not (application_packet_data[0] >> 7):
            return
        if not (application_packet_data[0] >> 6):
            ''' Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
            containing a zero value for this bit are not valid packets in this
            version and MUST be discarded.
            '''
            return
        flow.set_protocol(self.quic_label)
