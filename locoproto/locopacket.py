import struct
import bson

class LocoPacket:
    def __init__(self, id_: int, status: int, method: str, type_: int, body: dict):
        if isinstance(method, bytes):
            method = method.decode('ascii')
        self.id = id_
        self.status = status
        self.method = method.strip('\x00')
        self.type = type_
        self.body = body

    def __repr__(self):
        return f'<LocoPacket id={self.id} status={self.status} method={self.method} type={self.type} body={self.body}>'

    @classmethod
    def from_bytes(cls, data: bytes) -> LocoPacket:
        new = cls(*struct.unpack('<IH11sB', data[:18]), bson.loads(data[22:]))
        return new

    def to_bytes(self) -> bytes:
        body = bson.dumps(self.body)
        return struct.pack('<IH11sBI', self.id, self.status,
                           self.method.encode('ascii'), self.type, len(body)) + body
