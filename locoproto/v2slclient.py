from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.hazmat.primitives.ciphers as ciphers
import struct
import secrets

from typing import List

LOCO_PUBLICKEY = serialization.load_pem_public_key(b"""
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAA
OCAQ0AMIIBCAKCAQEApElgRBx+
g7sniYFW7LE8ivrwXShKTRFV8l
XNItMXbN5QSC8vJ/cTSOTS619X
v5Zx7xXJIk4EKxtWesEGbgZpEU
P2xQ+IeH9oz0JxayEMvvD1nVNA
WgpWE4pociEoArsK7qY3YwXb1C
iDHo9hojLv7djbo3cwXvlyMh4T
UrX2RjCZPlVJxk/LVjzcl9ohJL
kl3eoSrf0AE4kQ9mk3+raEhq5D
v+IDxKYX+fIytUWKmrQJusjtre
9oVUX5sBOYZ0dzez/XapusEhUW
ImmB6mciVXfRXQ8IK4IH6vfNyx
MSOTfLEhRYN2SMLzplAYFiMV53
6tLS3VmG5GJRdkpDubqPeQIBAw==
-----END PUBLIC KEY-----"""
)

class V2SLClient:
    """
    V2SL Socket Client
    """
    def __init__(self):
        self._aeskey = secrets.randbits(128).to_bytes(16, "little")
        self._readbuf = bytearray()
        self._handshaked = False
        
    def handshake(self):
        encrypted_key = LOCO_PUBLICKEY.encrypt(
            self._aeskey,
            padding.OAEP(
                padding.MGF1(hashes.SHA1()),
                hashes.SHA1(), None
            )
        )
        handshake_pkt = struct.pack("<III", len(encrypted_key), 12, 2) + encrypted_key
        return handshake_pkt
        
    def _send(self, data: bytes) -> bytes:
        iv = secrets.randbits(128).to_bytes(16, "little")
        self._aes = ciphers.Cipher(
            ciphers.algorithms.AES(self._aeskey),
            ciphers.modes.CFB(iv)
        )
        enc = self._aes.encryptor()
        enc_data = enc.update(data) + enc.finalize()
        enc_pkt = struct.pack("<I", len(enc_data)+16) + iv + enc_data
        return enc_pkt
        
    def _recv(self) -> bytes:
        if len(self._readbuf) < 4:
            return None
        enc_len, = struct.unpack("<I", self._readbuf[:4])
        if len(self._readbuf[4:]) < enc_len:
            return None
        dec = self._aes.decryptor()
        data = dec.update(self._readbuf[4:4+enc_len]) + dec.finalize()
        del self._readbuf[:4+enc_len]
        iv = data[:16]
        return data[16:]

    def send(self, data: bytes, split=2048) -> List[bytes]:
        segments = []
        if not self._handshaked:
            self._handshaked = True
            segments.append(self.handshake())
        sentbytes = 0
        while sentbytes < len(data):
            segments.append(self._send(data[sentbytes:sentbytes+split]))
            sentbytes += split
        return segments

    def recv(self, data) -> List[bytes]:
        segments = []
        self._readbuf += data
        while (segment := self._recv()):
            segments.append(segment)
        return segments
