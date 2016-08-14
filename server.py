# env/bin python
# -*- coding: utf-8 -*-
"""DNS server."""
import asyncio
import struct
import requests


class DNSHeader:
    """
    https://www.ietf.org/rfc/rfc1035.txt
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    """
    __slots__ = ('ID', 'QR', 'Opcode', 'AA', 'TC', 'RD', 'RA', 'RCODE', 'QDCOUNT', 'ANCOUNT', 'NSCOUNT', 'ARCOUNT')

    def __init__(self):
        for k in self.__slots__:
            self.__setattr__(k, 0)

    @classmethod
    def decode(cls, data):
        h = DNSHeader()
        # 1-2 byte
        h.ID, = struct.unpack('>H', data[0:2])
        # 3 byte
        h.QR = (data[2] & 0x80) >> 7
        h.Opcode = (data[2] & 0x78) >> 3
        h.AA = (data[2] & 0x04) >> 2
        h.TC = (data[2] & 0x02) >> 1
        h.RD = (data[2] & 0x01)
        # 4 byte
        h.RA = (data[3] & 0x80) >> 7
        h.RCODE = (data[3] & 0x0f)
        # 5-6 byte
        h.QDCOUNT, = struct.unpack('>H', data[4:6])
        # 7-8 byte
        h.ANCOUNT, = struct.unpack('>H', data[6:8])
        # 9-10 byte
        h.NSCOUNT, = struct.unpack('>H', data[8:10])
        # 11-12 byte
        h.ARCOUNT, = struct.unpack('>H', data[10:12])

        return h

    @classmethod
    def encode(cls, h):
        ret = bytes()
        ret += struct.pack('>H', h.ID)  # 1 2
        ret += bytes([  # 3 4
                (h.QR & 0x01) << 7 | (h.Opcode & 0x0f) << 3 | (h.AA & 0x01) << 2 | (h.TC & 0x01) << 1 | (h.RD & 0x01),
                (h.RA & 0x01) << 7 | (h.RCODE & 0x0f),
            ])
        ret += struct.pack('>H', h.QDCOUNT)
        ret += struct.pack('>H', h.ANCOUNT)
        ret += struct.pack('>H', h.NSCOUNT)
        ret += struct.pack('>H', h.ARCOUNT)
        return ret

    def __str__(self):
        s = ''
        for k in self.__slots__:
            s += '%7s:%s\n' % (k, self.__getattribute__(k))
        return s


class DNSQuestion:
    __slots__ = ('QName', 'QType', 'QClass')

    def __init__(self):
        self.QName = b''
        self.QType = 0
        self.QClass = 0

    @classmethod
    def decode(cls, data):
        q = DNSQuestion()
        cur = 0
        while data[cur]:
            length = data[cur]
            q.QName += data[cur + 1: cur + length + 1]
            cur += length + 1
            q.QName += b'.' if data[cur] else b''
        cur += 1
        print('cur%s' % cur)
        data = data[cur:]
        q.QType, = struct.unpack('>H', data[0:2])
        q.QClass, = struct.unpack('>H', data[2:4])
        return q, data

    @classmethod
    def encode(cls, q):
        ret = bytes([])
        for p in q.QName.split(b'.'):
            ret += bytes([len(p)])
            ret += p
        ret += bytes([0])
        ret += struct.pack('>H', q.QType)
        ret += struct.pack('>H', q.QClass)
        return ret

    def __str__(self):
        s = ''
        for k in self.__slots__:
            s += '%7s:%s\n' % (k, self.__getattribute__(k))
        return s


class DNSResource:
    __slots__ = ('NAME', 'TYPE', 'CLASS', 'TTL', 'RDLENGTH', 'RDATA')

    def __init__(self):
        for k in self.__slots__:
            self.__setattr__(k, 0)

    @classmethod
    def encode(cls, r):
        ret = bytes()
        if isinstance(r.NAME, int):  # offset
            # The OFFSET field specifies an offset from
            # the start of the message (i.e., the first octet of the ID field in the
            # domain header).
            NAME = struct.pack('>H', r.NAME)
            ret += bytes([NAME[0] | 0xc0, NAME[1]])
        else:
            ret += r.NAME
        ret += struct.pack('>H', r.TYPE)
        ret += struct.pack('>H', r.CLASS)
        ret += struct.pack('>I', r.TTL)
        ret += struct.pack('>H', r.RDLENGTH)
        ret += r.RDATA
        return ret


class DNSProtocol(asyncio.DatagramProtocol):

    def __init__(self, loop):
        self.transport = None
        self.loop = loop

    async def resolve(self, header, question, addr):
        data = bytes()
        h = DNSHeader()
        h.QR = 1
        h.ID = header.ID
        h.QDCOUNT = 1  # origin query
        h.ANCOUNT = 1
        data += DNSHeader.encode(h)
        data += DNSQuestion.encode(question)
        ans = DNSResource()
        'NAME', 'TYPE', 'CLASS', 'TTL', 'RDLENGTH', 'RDATA'
        ans.NAME = 0x0c  # 12 , first question
        ans.TYPE = question.QType
        ans.CLASS = question.QClass
        ans.TTL = 600
        ans.RDLENGTH = 4
        ans.RDATA = bytes([1, 2, 3, 4])
        data += DNSResource.encode(ans)
        self.transport.sendto(data, addr)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print('Received %r bytes from %s' % (len(data), addr))
        h = DNSHeader.decode(data[:12])
        if h.Opcode != 0 or h.QDCOUNT != 1:
            return
        print(h)
        if h.QDCOUNT:
            q, _ = DNSQuestion.decode(data[12:])
            print(q)
            if q.QType == 1 and q.QClass == 1:
                asyncio.ensure_future(self.resolve(h, q, addr), loop=self.loop)


def main():
    loop = asyncio.get_event_loop()

    listen = loop.create_datagram_endpoint(lambda: DNSProtocol(loop), local_addr=('0.0.0.0', 53))
    transport, protocol = loop.run_until_complete(listen)
    loop.run_forever()

if __name__ == '__main__':
    main()
