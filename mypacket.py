from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import *
from playground.network.packet.fieldtypes.attributes import *
import zlib
import uuid
import random
import time
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime


class RequestToConnect(PacketType):
    DEFINITION_IDENTIFIER = "RequestToConnect"
    DEFINITION_VERSION = "1.0"


class NameRequest(PacketType):
    DEFINITION_IDENTIFIER = "NameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("question", STRING)
    ]


class AnswerNameRequest(PacketType):
    DEFINITION_IDENTIFIER = "AnswerNameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("name", STRING)
    ]


class Result(PacketType):
    DEFINITION_IDENTIFIER = "result"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("result", BOOL)
    ]


class PEEPPacket(PacketType):
    DEFINITION_IDENTIFIER = "PEEP.Packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Type", UINT8),
        ("SequenceNumber", UINT32({Optional: True})),
        ("Checksum", UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
    ]

    def updateSeqAcknumber(self, seq, ack):
        self.SequenceNumber = seq
        self.Acknowledgement = ack

    def calculateChecksum(self):
        oldChecksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = oldChecksum
        return zlib.adler32(bytes) & 0xffff

    def updateChecksum(self):
        self.Checksum = self.calculateChecksum()

    def verifyChecksum(self):
        return self.Checksum == self.calculateChecksum()

# SYN -      TYPE 0
# SYN-ACK -  TYPE 1
# ACK -      TYPE 2
# RIP -      TYPE 3
# RIP-ACK -  TYPE 4
# DATA -      TYPE 5

'''
    def generateNonce(self,length):
        """Generate pseudo-random number."""
        return ''.join([str(random.randint(0, 9)) for i in range(length)])

    def generate_timestamp(self):
        """Get seconds since epoch (UTC)."""
        return str(int(time.time()))

    def generate_nonce_timestamp(self):
        """Generate pseudo-random number and seconds since epoch (UTC)."""
        nonce = uuid.uuid1()
        oauth_timestamp, oauth_nonce = str(nonce.time), nonce.hex
        return oauth_nonce, oauth_timestamp'''

class PacketBaseType(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.base"
    DEFINITION_VERSION = "1.0"
    FIELDS = []



class PlsHello(PacketBaseType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Nonce", UINT64),
        ("Certs", LIST(BUFFER))
    ]
    def generateNonce(self,length):
        """Generate pseudo-random number."""
        return random.getrandbits(length)
    def generateCerts(self):
        """Generate Certs for PLS"""
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Baltimore"
        cert.get_subject().L = "Baltimore"
        cert.get_subject().O = "netsec fall17"
        cert.get_subject().OU = "netsec fall17"
        cert.get_subject().CN = "fall 17"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')
        cert_buffer = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        #open(CERT_FILE, "wt").write(
        #    crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        #open(KEY_FILE, "wt").write(
        #    crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        return cert_buffer


class PlsKeyExchange(PacketBaseType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.keyexchange"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("PreKey", BUFFER),
        ("NoncePlusOne", UINT64),
    ]
    def generatePrekey(self):
        key_buffer = ""
        return key_buffer




class PlsHandshakeDone(PacketBaseType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.handshakedone"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("ValidationHash", BUFFER)
  ]

class PlsData(PacketBaseType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.data"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Ciphertext", BUFFER),
    ("Mac", BUFFER)
  ]

class PlsClose(PacketBaseType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Error", STRING({Optional: True}))
  ]
