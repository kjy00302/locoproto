import struct
from .locopacket import LocoPacket
from .v2slclient import V2SLClient
from typing import List

class LocoClient:
    def __init__(self):
        self._v2sl = V2SLClient()
        self._readbuf = bytearray()
        self._pktcnt = 1

    def sendpacket(self, pkt: LocoPacket) -> List[bytes]:
        pkt.id = self._pktcnt
        ret = self._v2sl.send(pkt.to_bytes())
        self._pktcnt += 1
        return ret

    def getpacket(self) -> LocoPacket:
        if len(self._readbuf) < 22:
            return None
        pkt_len, = struct.unpack('<I', self._readbuf[18:22])
        if len(self._readbuf) < 22 + pkt_len:
            return None
        pkt = LocoPacket.from_bytes(self._readbuf[:22+pkt_len])
        del self._readbuf[:22+pkt_len]
        return pkt

    def recvdata(self, data):
        for segment in self._v2sl.recv(data):
            self._readbuf += segment

    def sendraw(self, data: bytes, split: int=2048) -> List[bytes]:
        return self._v2sl.send(data, split)

    def recvraw(self, size=-1) -> bytes:
        if size == -1:
            ret = self._readbuf[:]
            del self._readbuf[:]
            return ret
        ret = self._readbuf[:size]
        del self._readbuf[:size]
        return ret
