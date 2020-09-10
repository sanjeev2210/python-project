import socket, os, logging, time, struct
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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

uint8  = ctypes.c_uint8.__ctype_be__
uint16 = ctypes.c_uint16.__ctype_be__
uint32 = ctypes.c_uint32.__ctype_be__
uint64 = ctypes.c_uint64.__ctype_be__

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


DTLS_VERSION = (b'\xfe\xfd')

count = -1
packetCount = 0

serverIP = '127.0.0.1'
serverPort = 28000
bufferSize = 4096
dtlsVersion = 65277
handshake = 22

cipherList = [156, 157]
cipherLen = 4

#TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
#TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256


CA_List = ['wipro.com', 'broadcom.com', 'google.com']

bb = bytearray()
bb.extend(uint32(int(time.time())))
bb.extend(urandom(28))
clientRandom = bb


preMasterSecret = urandom(46)
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

    #ClientHello with cookie and ClientHello without cookie packet specification
    def clientHello(self, rObj, hObj, socket, isCookie):
        global packetCount
        global count
        print("count", count)
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
        else:
            serialize.extend(uint16(95))
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


        socket.sendto(serialize, (serverIP, serverPort))
        del serialize

    #Converting the incoming certificate into PEM format
    def getPEMFormatCert(self, aData):
        p_type = "CERTIFICATE"
        data = '-'*5+"BEGIN "+p_type+'-'*5+'\n'+ aData.encode("base64")+'-'*5+"END "+p_type+'-'*5
        #print("gg", data, len(data))
        cert = x509.load_pem_x509_certificate(data, default_backend())
        return cert

    #Client will validate to authenticate server identity by:
        #1. Check the validity
        #2. CA's public key will validate the issuer digital signature
        #3. Issuing CA is trusted CA or, not ?
    def verifyCertificate(self, hObj, data):
        cert = self.getPEMFormatCert(data)

        #verify validity of certificate
        before = cert.not_valid_before
        after = cert.not_valid_after
        BEFORE_DATE = datetime.datetime(day=before.day, month=before.month, year=before.year)
        AFTER_DATE = datetime.datetime(day=after.day, month=after.month, year=after.year)
        TODAY_DATE = datetime.datetime.now()
        if BEFORE_DATE <= TODAY_DATE <= AFTER_DATE:
            print("Validity passed....")
        else:
            raise Exception("Certificate expired...")

        #Validating the issuer digital signature by CA's Public key
        issuer_public_key = cert.public_key()
        hObj.sharedPublicKey = issuer_public_key
        #print("ssss", cert.signature, cert.signature_hash_algorithm, dir(cert))
        # sigCheck = issuer_public_key.verify(
        #          cert.signature,
        #          cert.tbs_certificate_bytes,
        #          padding.PKCS1v15(),
        #          cert.signature_hash_algorithm,
        #         )
        # print("siggggg", cert.signature, cert.signature_hash_algorithm)
        # if sigCheck is not None:
        #     raise Exception("CA's Public key unable to validate issuer digital signature")

        # print("Server Certificate verified......")

        # #checking the issuing CA is trusted CA or, not
        # commonAttribute = cert.subject.rfc4514_string().split(',')[5]
        # commonName = commonAttribute[3:]
        # if commonName not in CA_List:
        #     raise Exception("Issuing CA is not trusted CA")


    def getRSAEncryptedSecret(self, hObj):
        publicKey = hObj.sharedPublicKey
        clientVersion = bytearray()
        clientVersion.extend(uint16(dtlsVersion))
        finalSecret = str(clientVersion) + preMasterSecret
        del clientVersion
        #print("preMasterSecret", preMasterSecret)
        encryptedSecret = publicKey.encrypt(
            finalSecret,
            padding.PKCS1v15()
            )
        hObj.rsaEncryptedPreMasterSecret = encryptedSecret
        hObj.rsaEncryptedPreMasterLength = len(hObj.rsaEncryptedPreMasterSecret)

    def clientKeyExchange(self, rObj, hObj, serialize):
        global count
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 0
        serialize.extend(uint16(rObj.epoch))
        count += 1
        rObj.seqNumber = count
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = hObj.rsaEncryptedPreMasterLength + 14
        serialize.extend(uint16(rObj.length))
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

    def cipherSpecChange(self, rObj, serialize):
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

    def encryptedHandshakeMessage(self, rObj, hObj, kObj, serialize):
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 1
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 0
        serialize.extend(uint48(rObj.seqNumber))

        handMessage = self.PRFforHandshake(hObj)

        self.getKeyFromMaster(hObj, kObj)

        iv = kObj.client_write_IV
        encryptor = Cipher(
            algorithms.AES(kObj.client_write_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(kObj.client_write_MAC_key)
        ciphertext = encryptor.update(handMessage) + encryptor.finalize()

        rObj.length = len(ciphertext)
        serialize.extend(uint16(rObj.length))
        serialize.extend(ciphertext)

    def clientKeyExchange2(self, rObj, hObj, socket):
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
        socket.sendto(serialize, (serverIP, serverPort))
        del serialize

    def cipherSpecChange2(self, rObj, socket):
        global count
        serialize = bytearray()
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
        socket.sendto(serialize, (serverIP, serverPort))
        del serialize

    def encryptedHandshakeMessage2(self, rObj, hObj, kObj, socket):
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 1
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 1
        serialize.extend(uint48(rObj.seqNumber))

        handMessage = self.PRFforHandshake(hObj)

        self.getKeyFromMaster(hObj, kObj)

        iv = kObj.client_write_IV
        encryptor = Cipher(
            algorithms.AES(kObj.client_write_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(kObj.client_write_MAC_key)
        ciphertext = encryptor.update(handMessage) + encryptor.finalize()
        print("encryptor====================", ciphertext)

        rObj.length = len(ciphertext)
        serialize.extend(uint16(rObj.length))
        serialize.extend(ciphertext)
        socket.sendto(serialize, (serverIP, serverPort))
        del serialize

    def PRFforHandshake(self, hObj):
        masterSecretVal = self.generateMasterSecret(hObj)
        hObj.masterSecret = masterSecretVal

        m = hashlib.sha256()
        m.update("ClientHello")
        m.update("ServerHello")
        m.update("Certificate")
        m.update("ServerHelloDone")
        m.update("ClientKeyExchange")
        m.update("Finished")
        seed = m.digest()
        label = bytearray("client finished")
        labelAndSeed = bytes_encode(label)
        labelAndSeed += bytes_encode(seed)

        a0 = labelAndSeed
        a1 = hmac.new(masterSecretVal, a0, hashlib.sha256).digest()
        a2 = hmac.new(masterSecretVal, a1, hashlib.sha256).digest()

        p1 = hmac.new(masterSecretVal, a1 + labelAndSeed, hashlib.sha256).digest()
        p2 = hmac.new(masterSecretVal, a2 + labelAndSeed, hashlib.sha256).digest()

        finalVal = p1 + p2[:16]

        return finalVal


    def generateMasterSecret(self, hObj):
        label = bytearray("master secret")
        seed = clientRandom + hObj.serverRandom

        labelAndSeed = bytes_encode(label)
        labelAndSeed += bytes_encode(seed)

        a0 = labelAndSeed
        a1 = hmac.new(preMasterSecret, a0, hashlib.sha256).digest()
        a2 = hmac.new(preMasterSecret, a1, hashlib.sha256).digest()

        p1 = hmac.new(preMasterSecret, a1 + labelAndSeed, hashlib.sha256).digest()
        p2 = hmac.new(preMasterSecret, a2 + labelAndSeed, hashlib.sha256).digest()

        masterVal = p1 + p2[:16]

        return masterVal

    def additionalKeyFromMasterSecret(self, hObj):
        masterSecretVal = hObj.masterSecret
        label = bytearray("key expansion")
        seed = clientRandom + hObj.serverRandom

        labelAndSeed = bytes_encode(label)
        labelAndSeed += bytes_encode(seed)

        a0 = labelAndSeed
        a1 = hmac.new(masterSecretVal, a0, hashlib.sha256).digest()
        a2 = hmac.new(masterSecretVal, a1, hashlib.sha256).digest()
        a3 = hmac.new(masterSecretVal, a2, hashlib.sha256).digest()
        a4 = hmac.new(masterSecretVal, a3, hashlib.sha256).digest()

        p1 = hmac.new(masterSecretVal, a1 + labelAndSeed, hashlib.sha256).digest()
        p2 = hmac.new(masterSecretVal, a2 + labelAndSeed, hashlib.sha256).digest()
        p3 = hmac.new(masterSecretVal, a3 + labelAndSeed, hashlib.sha256).digest()
        p4 = hmac.new(masterSecretVal, a4 + labelAndSeed, hashlib.sha256).digest()

        p = p1 + p2 + p3 + p4

        return p

    def getKeyFromMaster(self, hObj, kObj):
        key_block = self.additionalKeyFromMasterSecret(hObj)
        kObj.client_write_MAC_key = key_block[0:20]
        kObj.server_write_MAC_key = key_block[20:40]
        kObj.client_write_key = key_block[40:56]
        kObj.server_write_key = key_block[56:72]
        kObj.client_write_IV = key_block[72:88]
        kObj.server_write_IV = key_block[88:104]

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
                self.getRSAEncryptedSecret(self.handObj)
            else:
                serialization = bytearray()
                self.clientKeyExchange(self.recObj, self.handObj, serialization)
                self.cipherSpecChange(self.recObj, serialization)
                self.encryptedHandshakeMessage(self.recObj, self.handObj, self.keyObj, serialization)
                sock.sendto(serialization, (serverIP, serverPort))
                del serialization
                self.clientKeyExchange2(self.recObj, self.handObj, sock)
                self.cipherSpecChange2(self.recObj, sock)
                self.encryptedHandshakeMessage2(self.recObj, self.handObj, self.keyObj, sock)

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
    epochNO = ""
    dtlsObj = DTLS()
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
            print("Handshake Negotiation finished from server side...")
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

            print("seqNo", seqNo)

            if seqNo == hello_verify_request:
                addVal = data[28:]
            elif seqNo == server_hello:
                dtlsObj.updateRandom(data[27:59])
            elif seqNo == certificate and certFlag==True:
                certVal += data[31:]
            elif seqNo == application_data:
                adVal = data[13:]
                dtlsObj.pickRequest(clientSocket, seqNo, adVal)


if __name__ == "__main__":
    main()
