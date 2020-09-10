import socket, os, logging, time, struct, ssl
import ctypes, ssl, datetime
import traceback
import hmac
import base64
import re,hashlib, binascii
from os import urandom
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

uint8  = ctypes.c_uint8.__ctype_be__
uint16 = ctypes.c_uint16.__ctype_be__
uint32 = ctypes.c_uint32.__ctype_be__
uint64 = ctypes.c_uint64.__ctype_be__

client_hello_flag = True
server_hello_flag = True
certificate_flag = True
server_hello_done_flag = True
client_key_exchange_flag = True
encrypted_handshake_flag = True

#For 3 bytes data
def uint24(val):
    return bytearray(uint32(val))[1:]

#For 6 bytes data
def uint48(val):
    return bytearray(uint64(val))[2:]

#Encode to bytes
def bytes_encode(x):
    if isinstance(x, str):
        return x.encode("base64")
    return bytes(x)


DTLS_VERSION = b'\xfe\xfd'

handshake_messages = []

count = -1
packetCount = 0

serverIP = '127.0.0.1'
serverPort = 28000
bufferSize = 4096
dtlsVersion = 65277
handshake = 22

cipherList = [156, 157]
cipherLen = 4

#TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009c)
#TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0x009d)

#TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)




CA_List = ['wipro.com', 'broadcom.com', 'google.com']


bb = bytearray()
bb.extend(uint32(int(time.time())))
bb.extend(urandom(28))
clientRandom = bb


preMasterSecret = DTLS_VERSION + urandom(46)
preMasterSecret1 = urandom(48)

client_hello = 1
server_hello = 2
hello_verify_request = 3
certificate = 11
server_hello_done = 14
client_key_exchange = 16
change_cipher_spec = 20
finished = 0
application_data = 23

class Record_Layer:
    def __init__(self):
        self.contentType = handshake
        self.version = dtlsVersion
        self.epoch = 0
        self.seqNumber = 0
        self.length = 0

class Handshake:
    def __init__(self):
        self.handShakeType = None
        self.version = dtlsVersion
        self.fragmentOffset = 0
        self.msgSequence = 0
        self.sessionID = 0
        self.cookieLength = 0
        self.cookie=None
        self.serverRandom = None
        self.cipherSuitesLength = 0
        self.cipherSuites=None
        self.length = 0
        self.fragmentLength = 0
        self.sharedPublicKey = None
        self.rsaEncryptedPreMasterLength = 0
        self.rsaEncryptedPreMasterSecret = None
        self.preMasterSecret = None
        self.masterSecret = None
        self.extension = None

class keyDerivation():
    def __init__(self):
        client_write_MAC_key = None
        server_write_MAC_key = None
        client_write_key = None
        server_write_key = None
        client_write_IV = None
        server_write_IV = None


class DTLS:
    def __init__(self):
        self.recObj = Record_Layer()
        self.handObj = Handshake()
        self.keyObj = keyDerivation()

    def _p_hash(self, hash_algorithm,  secret, seed, output_length):
        result = bytearray()
        i = 1
        while len(result) < output_length:
            h = HMAC(secret, hash_algorithm, default_backend())
            h.update(self._a(secret, hash_algorithm, i, seed))
            h.update(seed)
            result.extend(h.finalize())
            i += 1
        return bytes(result[:output_length])

    def _a(self, secret, hash_algorithm, n, seed):
        if n == 0:
            return seed
        else:
            h = HMAC(secret, hash_algorithm, default_backend())
            h.update(self._a(secret, hash_algorithm, n - 1, seed))
            return h.finalize()

    def prf(self, secret, label, seed, hash_algorithm, output_length):
        return self._p_hash(hash_algorithm, secret, label + seed, output_length)

    def int_to_bytes(self, value, length):
        result = []
        for i in range(0, length):
            result.append(value >> (i * 8) & 0xff)
        result.reverse()
        return str(result)

    def nb_to_n_bytes(self, number, size):
        h = '%x' % number
        s = binascii.unhexlify('0'*(size*2 - len(h)) + h)
        return s

    def clientHello(self, rObj, hObj, socket, isCookie):
        global packetCount
        global count
        #print("count", count)
        packetCount += 1
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        count += 1
        rObj.seqNumber = count
        serialize.extend(uint48(rObj.seqNumber))
        if isCookie is not None:
            serialize.extend(uint16(111))
            print("clientHello with cookie.....")
        else:
            serialize.extend(uint16(95))
            print("clientHello.....")

        record_layer_msg = serialize
        del serialize

        serialize = bytearray()

        hObj.handShakeType = client_hello
        serialize.extend(uint8(hObj.handShakeType))
        if isCookie is not None:
            serialize.extend(uint24(99))
        else:
            serialize.extend(uint24(83))
        if count <= 1:
            hObj.msgSequence = count
        else:
            hObj.msgSequence = 1
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        if isCookie is not None:
            serialize.extend(uint24(99))
        else:
            serialize.extend(uint24(83))
        serialize.extend(uint16(hObj.version))
        serialize.extend(clientRandom)
        serialize.extend(uint8(hObj.sessionID))
        if isCookie is not None:
            hObj.cookieLength = len(isCookie)
            serialize.extend(uint8(hObj.cookieLength))
            serialize.extend(isCookie)
        else:
            serialize.extend(uint8(hObj.cookieLength))
        hObj.cipherSuitesLength = cipherLen
        serialize.extend(uint16(hObj.cipherSuitesLength))
        hObj.cipherSuites = cipherList
        serialize.extend(uint16(hObj.cipherSuites[0]))
        serialize.extend(uint16(hObj.cipherSuites[1]))
        serialize.extend(uint8(1))
        serialize.extend(uint8(0))

        #For extension attributes
        serialize.extend(uint16(37))

        serialize.extend(uint16(11))
        serialize.extend(uint16(4))
        serialize.extend(uint8(3))
        serialize.extend(uint8(0))
        serialize.extend(uint8(1))
        serialize.extend(uint8(2))

        serialize.extend(uint16(10))
        serialize.extend(uint16(6))
        serialize.extend(uint16(4))
        serialize.extend(uint16(23))
        serialize.extend(uint16(25))

        serialize.extend(uint16(35))
        serialize.extend(uint16(0))

        serialize.extend(uint16(13))
        serialize.extend(uint16(6))
        serialize.extend(uint16(4))
        serialize.extend(uint16(1026))
        serialize.extend(uint16(1538))

        serialize.extend(uint16(15))
        serialize.extend(uint16(1))
        serialize.extend(uint8(1))

        handshake_layer_msg = serialize
        del serialize

        global client_hello_flag
        if isCookie is None and client_hello_flag == True:
            handshake_messages.append(str(handshake_layer_msg))
            client_hello_flag = False

        socket.sendto(record_layer_msg + handshake_layer_msg, (serverIP, serverPort))

    def getPEMFormatCert(self, aData):
        aData = aData[:529]
        p_type = "CERTIFICATE"
        data = '-'*5+"BEGIN "+p_type+'-'*5+'\n'+ aData.encode("base64")+'-'*5+"END "+p_type+'-'*5
        cert = x509.load_pem_x509_certificate(data, default_backend())
        return cert

    def verifyCertificate(self, hObj, data):
        cert = self.getPEMFormatCert(data)

        before = cert.not_valid_before
        after = cert.not_valid_after
        BEFORE_DATE = datetime.datetime(day=before.day, month=before.month, year=before.year)
        AFTER_DATE = datetime.datetime(day=after.day, month=after.month, year=after.year)
        TODAY_DATE = datetime.datetime.now()
        if BEFORE_DATE <= TODAY_DATE <= AFTER_DATE:
            print("Validity passed....")
        else:
            raise Exception("Certificate expired...")

        issuer_public_key = cert.public_key()
        hObj.sharedPublicKey = issuer_public_key
        #print("ssss", cert.signature, cert.signature_hash_algorithm, dir(cert))
        # sigCheck = issuer_public_key.verify(
        #          cert.signature,
        #          cert.tbs_certificate_bytes,
        #          padding.PKCS1v15(),
        #          cert.signature_hash_algorithm,
        #         )
        # if sigCheck is not None:
        #     raise Exception("CA's Public key unable to validate issuer digital signature")

        # print("Server Certificate verified......")

    def getRSAEncryptedSecret(self, hObj):
        publicKey = hObj.sharedPublicKey
        hObj.preMasterSecret = preMasterSecret
        encryptedSecret = publicKey.encrypt(hObj.preMasterSecret, padding.PKCS1v15())
        hObj.rsaEncryptedPreMasterSecret = encryptedSecret
        hObj.rsaEncryptedPreMasterLength = len(hObj.rsaEncryptedPreMasterSecret)

    def clientKeyExchange(self, rObj, hObj, b):
        print("clientKeyExchange.....")
        global count
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 0
        serialize.extend(uint16(rObj.epoch))
        count += 1
        rObj.seqNumber = count
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = hObj.rsaEncryptedPreMasterLength + 14
        serialize.extend(uint16(rObj.length))

        record_layer_msg = serialize
        del serialize
        serialize = bytearray()

        hObj.handShakeType = client_key_exchange
        serialize.extend(uint8(hObj.handShakeType))
        hObj.length = hObj.rsaEncryptedPreMasterLength + 2
        serialize.extend(uint24(hObj.length))
        hObj.msgSequence = 2
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        hObj.fragmentLength = hObj.rsaEncryptedPreMasterLength + 2
        serialize.extend(uint24(hObj.fragmentLength))
        serialize.extend(uint16(hObj.rsaEncryptedPreMasterLength))
        serialize.extend(hObj.rsaEncryptedPreMasterSecret)

        handshake_layer_msg = serialize
        del serialize
        b += record_layer_msg + handshake_layer_msg

        global client_key_exchange_flag
        if client_key_exchange_flag == True:
            handshake_messages.append(str(handshake_layer_msg))
            client_key_exchange_flag =  False

    def cipherSpecChange(self, rObj, b):
        print("cipherSpecChange.....")
        serialize =  bytearray()
        global count
        serialize.extend(uint8(change_cipher_spec))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 0
        serialize.extend(uint16(rObj.epoch))
        count += 1
        rObj.seqNumber = count
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = 1
        serialize.extend(uint16(rObj.length))
        changeCipherSpecMessage = 1
        serialize.extend(uint8(changeCipherSpecMessage))
        b += serialize
        del b

    def encryptedHandshakeMessage(self, rObj, hObj, kObj, b):
        print("encryptedHandshakeMessage.....")
        serialization = bytearray()
        serialization.extend(uint8(rObj.contentType))
        serialization.extend(uint16(rObj.version))
        rObj.epoch = 1
        serialization.extend(uint16(rObj.epoch))
        rObj.seqNumber = 0
        serialization.extend(uint48(rObj.seqNumber))

        masterSecretVal = self.prf(hObj.preMasterSecret, b'master secret', clientRandom + hObj.serverRandom,
                            hashes.SHA256(), 48)
        hObj.masterSecret = masterSecretVal
        key_expansion = self.prf(masterSecretVal, b'key expansion', clientRandom + hObj.serverRandom,
                            hashes.SHA256(), 200)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h = b''.join(handshake_messages)
        digest.update(h)
        seed = digest.finalize()

        final_handshake_msg = self.prf(masterSecretVal, b'client finished', seed, hashes.SHA256(), 12)

        bytes_to_msg = b'\x14' + self.nb_to_n_bytes(len(final_handshake_msg), 3) + final_handshake_msg

        handshake_messages.append(bytes_to_msg)

        self.deriveKey(hObj, kObj, key_expansion)

        iv = kObj.client_write_IV
        nonce = urandom(8)

        algorithm = algorithms.AES(kObj.client_write_key)

        auth_data = self.nb_to_n_bytes(0,8) + self.nb_to_n_bytes(22, 1) + DTLS_VERSION + self.nb_to_n_bytes(len(bytes_to_msg), 2)

        encryptor = Cipher(algorithm, modes.GCM(iv + nonce), backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(auth_data)
        result = encryptor.update(final_handshake_msg) + encryptor.finalize()
        print("length,,,,,", len(result), len(encryptor.tag), len(nonce))
        finalSecretMessage = nonce + result + encryptor.tag


        rObj.length = len(finalSecretMessage)
        serialization.extend(uint16(rObj.length))
        serialization.extend(finalSecretMessage)
        b += serialization
        del serialization

    def deriveKey(self, hObj, kObj, key_block):
        # kObj.client_write_MAC_key = key_block[0:0]
        # kObj.server_write_MAC_key = key_block[20:40]
        kObj.client_write_key = key_block[0:16]
        kObj.server_write_key = key_block[16:32]
        kObj.client_write_IV = key_block[32:36]
        kObj.server_write_IV = key_block[36:40]

    def startApplicationLayerMsg(self, hObj, kObj, rObj, socket):
        msgFromClient = "Hello"
        iv = kObj.client_write_IV
        encryptor = Cipher(
            algorithms.AES(kObj.client_write_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(kObj.client_write_MAC_key)
        ciphertext = encryptor.update(msgFromClient) + encryptor.finalize()
        serialize = bytearray()
        serialize.extend(uint8(application_data))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(1))
        rObj.seqNumber = 1
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = len(ciphertext) + len(encryptor.tag)
        serialize.extend(uint16(rObj.length))
        serialize.extend(encryptor.tag)
        serialize.extend(ciphertext)
        socket.sendto(serialize, (serverIP, serverPort))
        del serialize

    def decryptMessage(self, rObj, kObj, aVal):
        iv = kObj.server_write_IV
        tag = aVal[0:16]
        ciphertext = aVal[16:]
        decryptor = Cipher(
            algorithms.AES(kObj.server_write_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(kObj.server_write_MAC_key)

        decryptedVal = decryptor.update(ciphertext) + decryptor.finalize()
        print("decryptedVal", decryptedVal)

    def pickRequest(self, sock, reqType, addValue):
        if reqType == client_hello or reqType == hello_verify_request:
            self.clientHello(self.recObj, self.handObj, sock, addValue)
        elif reqType == server_hello_done:
            if addValue is not None:
                self.verifyCertificate(self.handObj, addValue)
                if self.handObj.rsaEncryptedPreMasterSecret is None:
                    self.getRSAEncryptedSecret(self.handObj)
            else:
                serialization = bytearray()
                self.clientKeyExchange(self.recObj, self.handObj, serialization)
                self.cipherSpecChange(self.recObj, serialization)
                self.encryptedHandshakeMessage(self.recObj, self.handObj, self.keyObj, serialization)
                sock.sendto(serialization, (serverIP, serverPort))
                del serialization

        elif reqType == handshake:
            print("Handshake Completed b/w server and client..................")
            self.startApplicationLayerMsg(self.handObj, self.keyObj, self.recObj, sock)
        elif reqType == application_data:
            self.decryptMessage(self.recObj, self.keyObj, addValue)

    def updateRandom(self, ranVal):
        self.handObj.serverRandom = ranVal

def main():
    clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.settimeout(1)
    seqNo = client_hello
    seqFlag = True
    certFlag = True
    addVal = ""
    certVal = ""
    certVal2 = ""
    epochNO = ""
    dtlsObj = DTLS()
    global server_hello_flag
    global certificate_flag
    global server_hello_done_flag
    while(True):
        if seqNo == client_hello:
            dtlsObj.pickRequest(clientSocket, seqNo, None)
        elif seqNo == hello_verify_request:
            dtlsObj.pickRequest(clientSocket, seqNo, addVal)
        elif seqNo == certificate:
            pass
        elif seqNo == server_hello_done:
            dtlsObj.pickRequest(clientSocket, seqNo, certVal)
            certFlag = False
            #print("Handshake Negotiation finished from server side...")
            dtlsObj.pickRequest(clientSocket, seqNo, None)
            #seqFlag = False
        elif seqNo == change_cipher_spec:
            print("Subsequent records will be protected now...")
        elif seqNo == handshake and epochNO == 1:
            dtlsObj.pickRequest(clientSocket, seqNo, None)
        try:
            msg = clientSocket.recvfrom(bufferSize)
            print("receiving........")
        except socket.timeout:
            continue
        except socket.error:
            break
        else:
            data = msg[0]
            if seqFlag:
                seqNo = int(data[13:14].encode('hex'), 16)
            else:
                seqNo = int(data[0:1].encode('hex'), 16)
                epochNO = int(data[3:5].encode('hex'), 16)

            if seqNo == hello_verify_request:
                addVal = data[28:]
            elif seqNo == server_hello:
                print("server_hello")
                handshake_layer_msg = data[13:]
                if server_hello_flag == True:
                    handshake_messages.append(str(handshake_layer_msg))
                dtlsObj.updateRandom(data[27:59])
            elif seqNo == certificate and certFlag == True:
                server_hello_flag = False
                if int(data[5:11].encode('hex'), 16) == 2:
                    certLen = int(data[28:31].encode('hex'), 16)
                    certVal += data[31:31+certLen]
                    certVal2 += data
                elif int(data[5:11].encode('hex'), 16) == 3:
                    certLen = int(data[37:40].encode('hex'), 16)
                    certVal += data[40:40+certLen]
                    certVal2 += data[37:40] + data[40:40+certLen]
                else:
                    pass
            elif seqNo == server_hello_done:
                if certificate_flag == True:
                    handshake_messages.append(str(certVal2[13:]))
                    certificate_flag = False
                if server_hello_done_flag == True:
                    handshake_messages.append(str(data[13:]))
                    server_hello_done_flag == False
            elif seqNo == application_data:
                adVal = data[13:]
                dtlsObj.pickRequest(clientSocket, seqNo, adVal)


if __name__ == "__main__":
    main()
