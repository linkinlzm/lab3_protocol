from playground.network.common import *
from .mypacket import *
from .CertFactory import *
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC, SHA256, SHA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
packet_size = 1000
window_size = 5
from binascii import hexlify

class item_list():
    sequenceNumber = 0
    SessionId = ''
    Acknowledgement = 0
    init_seq = 0
    outBuffer = b''
    readyToclose = False


class MyTransport(StackingTransport):
    def setinfo(self, info_list):
        self.info_list = info_list

    def write(self, data):  # this will be the data from the upper layer
        if len(self.info_list.outBuffer) < 3:
            self.info_list.init_seq = self.info_list.sequenceNumber

        if self.info_list.sequenceNumber == self.info_list.init_seq + len(self.info_list.outBuffer):
            self.info_list.outBuffer += data
            self.sent_data()
        else:
            self.info_list.outBuffer += data

            #

    def close(self):
        if self.info_list.readyToclose:
            self.lowerTransport().close()
        else:
            print("waiting...")

    def sent_data(self):
        # print(len(self.info_list.outBuffer))
        # print(self.info_list.sequenceNumber)
        small_packet = PEEPPacket()
        recordSeq = self.info_list.sequenceNumber
        for n in range(0, window_size):
            place_to_send = self.info_list.sequenceNumber - self.info_list.init_seq

            # print("inwrite:")
            # print(self.info_list.sequenceNumber)
            # print(self.info_list.init_seq)
            # print("my front length: " + str(front))
            if place_to_send + packet_size < len(self.info_list.outBuffer):
                # print("it should not be here")
                packet_data = self.info_list.outBuffer[place_to_send:place_to_send + packet_size]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
            else:

                packet_data = self.info_list.outBuffer[place_to_send:]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
                n = 999
            logging.info("this is the out seq number from write: " + str(self.info_list.sequenceNumber))
            small_packet.Type = 5  # data packet
            small_packet.Data = packet_data
            # small_packet.SessionId = self.info_list.SessionId
            small_packet.Checksum = small_packet.calculateChecksum()

            #print(self.lowerTransport().is_closing())
            self.lowerTransport().write(small_packet.__serialize__())

            if n > window_size:
                break
        self.info_list.sequenceNumber = recordSeq

    def get_data(self):
        return self.info_list.data

class PLSTransport(StackingTransport):
    def write(self, data):
        PLSpacket = PlsData()
        logging.info("PLS transport got data")
        ciphertext = self.enc_aes.update(data)
        logging.info("---------------Enc---------------")
        PLSpacket.Ciphertext = ciphertext
        hm1 = hmac.HMAC(self.mac, hashes.SHA1(), backend=default_backend())
        hm1.update(ciphertext)
        PLSpacket.Mac = hm1.finalize()
        self.lowerTransport().write(PLSpacket.__serialize__())

    def get_info(self, key, iv, mk):
        self.key = key
        self.iv = iv
        self.mac = mk
        # set up enc engine
        self.enc_aes = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=default_backend()).encryptor()
        #iv_int = int(hexlify(self.iv), 16)
        #self.ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        #self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)

    def close(self):
        self.lowerTransport().close()




