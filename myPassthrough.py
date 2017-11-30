from .MyProtocolTransport import *
from .CertFactory import *
from playground.common.CipherUtil import RSA_SIGNATURE_MAC
import logging
import asyncio
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from Crypto.Hash import HMAC, SHA, SHA256
from binascii import hexlify
from OpenSSL import crypto
#logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
#logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

key_bytes = 32
# M1, C->S:  PlsHello(Nc, [C_Certs])
# M2, S->C:  PlsHello(Ns, [S_Certs])
# M3, C->S:  PlsKeyExchange( {PKc}S_public, Ns+1 )
# M4, S->C:  PlsKeyExchange( {PKs}C_public, Nc+1 )
# M5, C->S:  PlsHandshakeDone( Sha1(M1, M2, M3, M4) )
# M6, S->C:  PlsHandshakeDone( Sha1(M1, M2, M3, M4) )

# State machine for client SL
# 0: intial state, send C → S: PlsHello(Nc, [C_Certs])
# 1: receive PlsHello, send C->S:  PlsKeyExchange( {PKc}S_public, Ns+1 )
# 2: receive PlsKeyExchange, send PlsHandshakeDone
# 3: receive PlsHandshakeDone, handshake done
class PassThroughc1(StackingProtocol):
    def __init__(self):
        self.transport = None
        self.handshake = False
        self.higherTransport = None
        self._deserializer = PacketBaseType.Deserializer()
        self.state = 0
        self.C_Nonce = 0
        self.S_Nonce = 0
        self.S_Certs = []
        self.PKc = os.urandom(16)
        self.PKs = b''
        self.hashresult = hashlib.sha1()
        self.shash = hashlib.sha1()
        self.block = []

    def connection_made(self, transport):
        print("SL connection made")
        self.transport = transport
        address, port = transport.get_extra_info("sockname")
        self.C_Certs = getCertsForAddr(address)
        self.C_privKey = getPrivateKeyForAddr(address)
        helloPkt = PlsHello()
        self.C_Nonce = random.getrandbits(64)
        helloPkt.Nonce = self.C_Nonce
        helloPkt.Certs = self.C_Certs
        self.hashresult.update(helloPkt.__serialize__())
        self.transport.write(helloPkt.__serialize__())

    def data_received(self, data):
        #self.higherProtocol().data_received(data)
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PlsHello) and self.state == 0:
                print("client: PlsHello received")
                self.hashresult.update(pkt.__serialize__())
                self.S_Nonce = pkt.Nonce
                self.S_Certs = pkt.Certs
                address = self.transport.get_extra_info("peername")[0]
                if(verify_certchain(self.S_Certs, address)):
                    print("cert verified")
                else:
                    self.send_pls_close()
                    self.transport.close()
                keyExchange = PlsKeyExchange()
                keyExchange.PreKey = self.enc_prekey()
                keyExchange.NoncePlusOne = self.S_Nonce + 1
                self.state = 1
                self.hashresult.update(keyExchange.__serialize__())
                self.transport.write(keyExchange.__serialize__())
            elif isinstance(pkt, PlsKeyExchange) and self.state == 1:
                self.hashresult.update(pkt.__serialize__())
                print("client: PlsKeyExchange received")
                #check nc
                if pkt.NoncePlusOne == self.C_Nonce + 1:
                    print("client: check NC+1")
                    self.PKs = self.dec_prekey(pkt.PreKey)
                    hdshkdone = PlsHandshakeDone()
                    hdshkdone.ValidationHash = self.hashresult.digest()
                    self.state = 2
                    self.transport.write(hdshkdone.__serialize__())
                    print("client: send handshake done")
            elif isinstance(pkt, PlsHandshakeDone) and self.state == 2:
                # check hash
                if self.hashresult.digest() == pkt.ValidationHash:
                    print("-------------client: Hash Validated, PLS handshake done!-------------")
                    self.state = 3
                    self.handshake = True
                    self.gen_block()
                    self.higherTransport = PLSTransport(self.transport)
                    self.higherTransport.get_info(self.Ekc, self.IVc, self.MKc)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("client higher sent data")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                hm1 = HMAC.new(self.MKs, digestmod=SHA)
                hm1.update(pkt.Ciphertext)
                verifyMac = hm1.digest()
                if (verifyMac == pkt.Mac):
                    plaintext = decrypt(self.enc_aes, pkt.Ciphertext)
                    logging.info("--------------Mac Verified---------------")
                    self.higherProtocol().data_received(plaintext)
                else:
                    self.send_pls_close("Mac Verification Failed")
                    self.higherTransport.close()
            elif isinstance(pkt, PlsClose):
                normal_close = PlsClose()
                PlsClose.Error = None
                if pkt == normal_close:
                    print("\n----------PLS Close: Normal Shut Down!----------")
                else:
                    print("\n----------PLS Close: %s----------" % pkt.Error)
                self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def enc_prekey(self):
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.S_Certs[0])
        pubKeyObject = crtObj.get_pubkey()
        pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
        key = RSA.importKey(pubKeyString)
        Encrypter = PKCS1OAEP_Cipher(key, None, None, None)
        return Encrypter.encrypt(self.PKc)

    def dec_prekey(self, ciphertext):
        CpriK = RSA.importKey(self.C_privKey)
        Decrypter = PKCS1OAEP_Cipher(CpriK, None, None, None)
        return Decrypter.decrypt(ciphertext)

    def gen_block(self):
        block_0 = hashlib.sha1(b"PLS1.0" + self.C_Nonce.to_bytes(8, byteorder='big') + self.S_Nonce.to_bytes(8,byteorder='big') + self.PKc + self.PKs).digest()
        block_1 = hashlib.sha1(block_0).digest()
        block_2 = hashlib.sha1(block_1).digest()
        block_3 = hashlib.sha1(block_2).digest()
        block_4 = hashlib.sha1(block_3).digest()
        block_bytes = block_0 + block_1 + block_2 + block_3 + block_4
        # print(len(self.block_bytes))
        self.Ekc = block_bytes[0:16]
        self.Eks = block_bytes[16:32]
        self.IVc = block_bytes[32:48]
        self.IVs = block_bytes[48:64]
        self.MKc = block_bytes[64:80]
        self.MKs = block_bytes[80:96]

        iv_int = int(hexlify(self.IVs), 16)
        self.enc_ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        # Create AES-CTR cipher.
        self.enc_aes = AES.new(self.Eks, AES.MODE_CTR, counter=self.enc_ctr)

    def send_pls_close(self, error_info=None):
        err_packet = PlsClose()
        err_packet.Error = error_info
        self.transport.write(err_packet.__serialize__())


# State machine for server SL
# 0: initial state, wait for PlsHello
# 1: receive PlsHello, send PlsKeyExchange( {PKs}C_public, Nc+1 )
# 2: receive PlsKeyExchange, send PlsKeyExchange
# 3: receive PlsHandshakeDone, send PlsHandshakeDone, check hash value, handshake done
class PassThroughs1(StackingProtocol):
    def __init__(self):
        self.transport = None
        self.handshake = False
        self.higherTransport = None
        self._deserializer = PacketBaseType.Deserializer()
        self.state = 0
        self.C_Nonce = 0
        self.S_Nonce = 0
        self.C_Certs = []
        self.PKs = os.urandom(16)
        self.PKc = b''
        self.hashresult = hashlib.sha1()
        self.shash = hashlib.sha1()
        self.block = []

    def connection_made(self, transport):
        print("SL connection made server")
        self.transport = transport
        address, port = transport.get_extra_info("sockname")
        self.S_Certs = getCertsForAddr(address)
        self.SPriK = getPrivateKeyForAddr(address)

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PlsHello) and self.state == 0:
                self.hashresult.update(bytes(pkt.__serialize__()))
                self.C_Nonce = pkt.Nonce
                self.C_Certs = pkt.Certs
                address = self.transport.get_extra_info("peername")[0]
                if (verify_certchain(self.C_Certs, address)):
                    logging.info("cert verified")
                else:
                    self.send_pls_close()
                    self.higherTransport.close("Cert Verification Failed")
                helloPkt = PlsHello()
                self.S_Nonce = random.getrandbits(64)
                helloPkt.Nonce = self.S_Nonce
                helloPkt.Certs = self.S_Certs
                self.hashresult.update(bytes(helloPkt.__serialize__()))
                self.state = 1
                self.transport.write(helloPkt.__serialize__())
                logging.info("server: PlsHello sent")
            elif isinstance(pkt, PlsKeyExchange) and self.state == 1:
                self.hashresult.update(bytes(pkt.__serialize__()))
                # check nc
                if pkt.NoncePlusOne == self.S_Nonce + 1:
                    logging.info("server: check NC+1")
                    self.PKc = self.dec_prekey(pkt.PreKey)
                    keyExchange = PlsKeyExchange()
                    keyExchange.PreKey = self.enc_prekey()
                    keyExchange.NoncePlusOne = self.C_Nonce + 1
                    self.hashresult.update(bytes(keyExchange.__serialize__()))
                    self.state = 2
                    self.transport.write(keyExchange.__serialize__())
                else:
                    logging.info("server: NC+1 error")
                    self.higherTransport.close("NC Verification Failed")
            elif isinstance(pkt, PlsHandshakeDone) and self.state == 2:
                hdshkdone = PlsHandshakeDone()
                hdshkdone.ValidationHash = self.hashresult.digest()
                logging.info("server: Reveive handshake done")
                # check hash
                if self.hashresult.digest() == pkt.ValidationHash:
                    self.state = 3
                    self.handshake = True
                    self.gen_block()
                    self.transport.write(hdshkdone.__serialize__())
                    self.higherTransport = PLSTransport(self.transport)
                    self.higherTransport.get_info(self.Eks, self.IVs, self.MKs)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("-------------server: Hash Validated, PLS handshake done!-------------")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                hm1 = HMAC.new(self.MKc, digestmod=SHA)
                hm1.update(pkt.Ciphertext)
                verifyMac = hm1.digest()
                if(verifyMac == pkt.Mac):
                    logging.info("--------------Mac Verified---------------")
                    plaintext = decrypt(self.enc_aes, pkt.Ciphertext)
                    self.higherProtocol().data_received(plaintext)
                else:
                    self.send_pls_close("Mac Verification Failed")
                    self.higherTransport.close()
            elif isinstance(pkt, PlsClose):
                normal_close = PlsClose()
                PlsClose.Error = None
                if pkt == normal_close:
                    print("\n----------PLS Close: Normal Shut Down!----------")
                else:
                    print("\n----------PLS Close: %s----------" % pkt.Error)
                    self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def enc_prekey(self):
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.C_Certs[0])
        pubKeyObject = crtObj.get_pubkey()
        pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
        key = RSA.importKey(pubKeyString)
        Encrypter = PKCS1OAEP_Cipher(key, None, None, None)
        return Encrypter.encrypt(self.PKs)

    def dec_prekey(self, ciphertext):
        CpriK = RSA.importKey(self.SPriK)
        Decrypter = PKCS1OAEP_Cipher(CpriK, None, None, None)
        return Decrypter.decrypt(ciphertext)

    def gen_block(self):
        block_0 = hashlib.sha1(b"PLS1.0" + self.C_Nonce.to_bytes(8, byteorder='big') + self.S_Nonce.to_bytes(8,byteorder='big') + self.PKc + self.PKs).digest()
        block_1 = hashlib.sha1(block_0).digest()
        block_2 = hashlib.sha1(block_1).digest()
        block_3 = hashlib.sha1(block_2).digest()
        block_4 = hashlib.sha1(block_3).digest()
        block_bytes = block_0 + block_1 + block_2 + block_3 + block_4
        # print(len(self.block_bytes))
        self.Ekc = block_bytes[0:16]
        self.Eks = block_bytes[16:32]
        self.IVc = block_bytes[32:48]
        self.IVs = block_bytes[48:64]
        self.MKc = block_bytes[64:80]
        self.MKs = block_bytes[80:96]

        iv_int = int(hexlify(self.IVc), 16)
        self.enc_ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        # Create AES-CTR cipher.
        self.enc_aes = AES.new(self.Ekc, AES.MODE_CTR, counter=self.enc_ctr)

    def send_pls_close(self, error_info=None):
        err_packet = PlsClose()
        err_packet.Error = error_info
        self.transport.write(err_packet.__serialize__())


def GetCommonName(cert):
    commonNameList = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(commonNameList) != 1: return None
    commonNameAttr = commonNameList[0]
    return commonNameAttr.value

def VerifyCertSignature(cert, issuer):
    try:
        issuer.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

def verify_certchain(certs,address):
    cert_chain = []
    for cert in certs:
        cert_chain.append(cert)
    cert_chain.append(getRootCert())
    X509_list = []
    crypto_list = []
    for cert in cert_chain:
        x509obj = x509.load_pem_x509_certificate(cert, default_backend())
        X509_list.append(x509obj)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        crypto_list.append(cert)

    # verify playground address
    logging.info("PLS received a connection from address {}".format(address))
    logging.info(
        "Common name: {}".format(X509_list[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
    logging.info(
        "Email address: {}".format(X509_list[0].subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value))
    if address == X509_list[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
        logging.info("Common name verified")
    else:
        logging.info("Common name error")
        return False
    for i in range(len(X509_list) - 1):
        this = X509_list[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if this.startswith(X509_list[i + 1].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value):
            logging.info("Address verified")
        else:
            return False
            logging.info("Address error")

    # verify the issuer and subject
    for i in range(len(crypto_list) - 1):
        issuer = crypto_list[i].get_issuer()
        logging.info(issuer)
        subject = crypto_list[i + 1].get_subject()
        logging.info(subject)
        if issuer == subject:
            logging.info("issuer and subject verified")
        else:
            return False

    # verify the signature sha256
    for i in range(len(X509_list) - 1):
        this = X509_list[i]
        # print(this)
        # print(this.signature)
        sig = RSA_SIGNATURE_MAC(X509_list[i + 1].public_key())
        # print(issuer)
        if not sig.verify(this.tbs_certificate_bytes, this.signature):
            return False
        else:
            logging.info("signature verified")
    return True

def decrypt(aes, ciphertext):

    # Decrypt and return the plaintext.
    plaintext = aes.decrypt(ciphertext)
    logging.info("-----------------Dec----------------")
    return plaintext




#


# state machine for client
# 0: initial state
# 1: SYN sent, wait for SYN-ACK
# 2: SYN-ACK received, sent ACK
class PassThroughc2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PEEPPacket.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.databuffer = ''
        self.timeout_timer = time.time()
        self.info_list = item_list()
        self.higherTransport = None
        self.lastcorrect = 0
        self.lastAck = 0
        self.close_timer = time.time()
        self.forceclose = 0

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                if self.lastAck > self.info_list.sequenceNumber:
                    self.info_list.sequenceNumber = self.lastAck
                self.ack_counter = 0
                self.timeout_timer = time.time()
                self.higherTransport.sent_data()
            else:
                print("client waiting...to...end")

        if time.time() - self.close_timer > 99999:
            self.forceclose += 1
            self.close_timer = time.time()
            Rip = PEEPPacket()
            Rip.Type = 3
            Rip.updateSeqAcknumber(self.info_list.sequenceNumber, ack=1)
            print("client: Rip sent")
            Rip.Checksum = Rip.calculateChecksum()
            self.transport.write(Rip.__serialize__())

            if self.forceclose > 5:
                self.info_list.readyToclose = True
                self.higherTransport.close()
                return

        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

    def resentsyn(self, pkt):
        if self.state == 0:
            self.transport.write(pkt.__serialize__())
            asyncio.get_event_loop().call_later(1, self.resentsyn, pkt)

    def connection_made(self, transport):
        self.transport = transport
        SYN = PEEPPacket()
        SYN.SequenceNumber = self.seq
        self.seq = self.seq + 1
        SYN.Type = 0  # SYN - TYPE 0
        SYN.Checksum = SYN.calculateChecksum()
        print("client: SYN sent")
        SYNbyte = SYN.__serialize__()
        self.transport.write(SYNbyte)
        self.resentsyn(SYN)

    def data_received(self, data):
        self.close_timer = time.time()
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 1 and self.state == 0 and not self.handshake:
                    print("SYN-ACK received")
                    if pkt.verifyChecksum():
                        ACK = PEEPPacket()
                        ACK.Type = 2  # ACK -  TYPE 2
                        self.seq = self.seq + 1
                        ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        print("client: ACK sent")
                        ACK.Checksum = ACK.calculateChecksum()
                        self.transport.write(ACK.__serialize__())
                        self.state = 1

                        print("ACK sent, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size
                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq - 1
                        self.info_list.init_seq = self.seq
                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)
                        self.handshake = True
                        self.transmit()


                        # client and server should be the same, start from here
                elif self.handshake:
                    if pkt.Type == 5:
                        if verify_packet(pkt, self.expected_packet+1):
                            # print("verify_packet from server")
                            self.lastcorrect = pkt.SequenceNumber + len(pkt.Data)
                            self.expected_packet = self.expected_packet + len(pkt.Data)
                            Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data))
                            # print("seq number:" + str(pkt.SequenceNumber))
                            self.transport.write(Ackpacket.__serialize__())
                            self.higherProtocol().data_received(pkt.Data)
                        else:

                            Ackpacket = generate_ACK(self.seq, self.lastcorrect)
                            # print("seq number:" + str(pkt.SequenceNumber))
                            print("the client ack number out last correct: " + str(self.lastcorrect))
                            self.transport.write(Ackpacket.__serialize__())

                    if pkt.Type == 2:
                        if verify_ack(pkt):
                            self.ack_counter = self.ack_counter + 1
                            # print(self.ack_counter)
                            # print("I got an ACK")
                            # print(pkt.Acknowledgement)
                            # print("ack number:" + str(pkt.Acknowledgement))

                            if self.info_list.sequenceNumber < pkt.Acknowledgement:
                                self.info_list.sequenceNumber = pkt.Acknowledgement
                                self.lastAck = pkt.Acknowledgement

                            if self.ack_counter == window_size and pkt.Acknowledgement < len(
                                    self.info_list.outBuffer) + self.seq:
                                self.timeout_timer = time.time()
                                print("next round")
                                # self.info_list.from_where = "passthough"
                                self.ack_counter = 0

                                if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.outBuffer):
                                    self.higherTransport.sent_data()

                            elif pkt.Acknowledgement == len(self.info_list.outBuffer) + self.seq:
                                self.seq = pkt.Acknowledgement
                                self.ack_counter = 0
                                self.higherTransport.setinfo(self.info_list)
                                print("done")
                    # improve this at lab3
                    if pkt.Type == 4:
                        print("get rip ack from server,close transport")
                        self.info_list.readyToclose = True
                        self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


#
# state machine for server
# 0: initial state, wait for SYN
# 1: received SYN, sent SYN-ACK, wait for ACK
# 2: ACK received, finished handshake
class PassThroughs2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PEEPPacket.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.info_list = item_list()
        self.timeout_timer = time.time()
        self.higherTransport = None
        self.lastcorrect = 0
        self.lastAck = 0
        self.close_timer = time.time()

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                if self.lastAck > self.info_list.sequenceNumber:
                    self.info_list.sequenceNumber = self.lastAck
                self.higherTransport.sent_data()
                self.timeout_timer = time.time()
                self.ack_counter = 0
            else:
                print("server waiting...for..RIP")
                if time.time() - self.close_timer > 30:
                    self.info_list.readyToclose = True
                    self.higherTransport.close()
                    return
        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

    def connection_made(self, transport):
        self.transport = transport

    def resentsynack(self, pkt):
        if self.state == 1:
            self.transport.write(pkt.__serialize__())
            asyncio.get_event_loop().call_later(1, self.resentsynack, pkt)

    def data_received(self, data):
        self.close_timer = time.time()
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 0 and self.state == 0:
                    if pkt.verifyChecksum():
                        print("received SYN")
                        SYN_ACK = PEEPPacket()
                        SYN_ACK.Type = 1
                        self.seq = self.seq + 1
                        SYN_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        SYN_ACK.Checksum = SYN_ACK.calculateChecksum()
                        print("server: SYN-ACK sent")
                        self.transport.write(SYN_ACK.__serialize__())
                        self.state = 1
                        self.resentsynack(SYN_ACK)

                elif pkt.Type == 2 and self.state == 1 and not self.handshake:
                    if pkt.verifyChecksum():
                        self.state = 3
                        print("got ACK, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal

                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size
                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq + 1
                        self.info_list.init_seq = self.seq

                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)
                        self.handshake = True
                        self.transmit()
                        break


                        # client and server should be the same, start from here
                elif self.handshake:
                    if pkt.Type == 5:
                        if verify_packet(pkt, self.expected_packet - 1):
                            # print("verify_packet from server")
                            self.lastcorrect = pkt.SequenceNumber + len(pkt.Data)
                            self.expected_packet = self.expected_packet + len(pkt.Data)
                            Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data))
                            # print("seq number:" + str(pkt.SequenceNumber))
                            self.transport.write(Ackpacket.__serialize__())
                            self.higherProtocol().data_received(pkt.Data)
                        else:
                            Ackpacket = generate_ACK(self.seq, self.lastcorrect)
                            # print("seq number:" + str(pkt.SequenceNumber))
                            print("the server ack number out last correct: " + str(self.lastcorrect))
                            self.transport.write(Ackpacket.__serialize__())

                    if pkt.Type == 2:
                        if verify_ack(pkt):
                            self.ack_counter = self.ack_counter + 1
                            # print(self.ack_counter)
                            # print("I got an ACK")
                            # print(pkt.Acknowledgement)
                            # print("ack number:" + str(pkt.Acknowledgement))

                            if self.info_list.sequenceNumber < pkt.Acknowledgement:
                                self.info_list.sequenceNumber = pkt.Acknowledgement
                                self.lastAck = pkt.Acknowledgement
                            if self.ack_counter == window_size and pkt.Acknowledgement < len(
                                    self.info_list.outBuffer) + self.seq:
                                self.timeout_timer = time.time()
                                print("next round")
                                # self.info_list.from_where = "passthough"
                                self.ack_counter = 0

                                if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.outBuffer):
                                    self.higherTransport.sent_data()

                            elif pkt.Acknowledgement == len(self.info_list.outBuffer) + self.seq:
                                self.seq = pkt.Acknowledgement
                                self.ack_counter = 0
                                self.higherTransport.setinfo(self.info_list)
                                print("done")

                    if pkt.Type == 3:
                        if self.info_list.sequenceNumber >= self.info_list.init_seq + len(self.info_list.outBuffer):
                            RIP_ACK = PEEPPacket()
                            RIP_ACK.Type = 4
                            RIP_ACK.updateSeqAcknumber(seq=self.info_list.sequenceNumber, ack=pkt.Acknowledgement)
                            RIP_ACK.Checksum = RIP_ACK.calculateChecksum()
                            print("server: RIP-ACK sent, ready to close")
                            self.transport.write(RIP_ACK.__serialize__())
                            self.info_list.readyToclose = True
                            self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


def verify_packet(packet, expected_packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    if expected_packet != packet.SequenceNumber:
        print("expect_number:" + str(expected_packet))
        print("packet number: " + str(packet.SequenceNumber))
        print("wrong packet seq number")
        goodpacket = False
    return goodpacket


def verify_ack(packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    return goodpacket


def generate_ACK(seq_number, ack_number):
    ACK = PEEPPacket()
    ACK.Type = 2
    ACK.SequenceNumber = seq_number
    ACK.Acknowledgement = ack_number
    # print("this is my ack number " + str(ack_number))
    ACK.Checksum = ACK.calculateChecksum()

    return ACK


    # FIELDS = [
    #     ("Type", UINT8),
    #     ("SequenceNumber", UINT32({Optional: True})),
    #     ("Checksum", UINT16),
    #     ("Acknowledgement", UINT32({Optional: True})),
    #     ("Data", BUFFER({Optional: True}))
    # ]
    # # Create MyProtocolPackets
    #     for each pkt in MyProtocolPackets:
    #         self.lowerTransport().write(pkt.__serialize__())

