import socket, os, logging, time, struct
import ctypes, ssl, datetime
import hmac
import base64
import re,hashlib, binascii
from os import urandom
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


uint8  = ctypes.c_uint8.__ctype_be__
uint16 = ctypes.c_uint16.__ctype_be__
uint32 = ctypes.c_uint32.__ctype_be__
uint64 = ctypes.c_uint64.__ctype_be__

clientRandom = urandom(28)
bb = bytearray()
bb.extend(uint32(int(time.time())))
bb.extend(urandom(28))
serverRandom = bb

def bytes_encode(x):
    if isinstance(x, str):
        return x.encode("base64")
    return bytes(x)

bufferSize = 4096
#serverIP = '10.122.34.155'
serverIP = '127.0.0.1'
serverPort = 1234
dtlsVersion = 65277
handshake = 22

cipherSupport = 157

cipherLen = 4


client_hello = 1
server_hello = 2
hello_verify_request = 3
certificate = 11
server_hello_done = 14
client_key_exchange = 16
change_cipher_spec = 20
finished = 0
application_data = 23


def uint24(val):
    return bytearray(uint32(val))[1:]

def uint48(val):
    return bytearray(uint64(val))[2:]


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
        self.clientRandom = None
        self.cipherSuitesLength = 0
        self.cipherSuites = None
        self.length = 0
        self.fragmentLength = 0
        self.certificateLength = 0
        self.certificate = None
        self.preMasterSecret = None
        self.masterSecret = None

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

    def generateCookie(self, address, key):
        peer_address = address
        cookie_hmac = hmac.new(key, str(peer_address))
        return cookie_hmac.digest()

    def verifyCookie(self, aCookie, address, key):
        print("3")
        if self.generateCookie(address, key) != aCookie:
            raise Exception("DTLS cookie mismatch...")
        else:
            print("Cookie verified....")

    def helloVerifyRequest(self, rObj, hObj, socket, address, rKey):
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        serialize.extend(uint48(rObj.seqNumber))
        serialize.extend(uint16(31))
        hObj.handShakeType = hello_verify_request
        serialize.extend(uint8(hObj.handShakeType))
        serialize.extend(uint24(22))
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        serialize.extend(uint24(22))
        serialize.extend(uint16(hObj.version))
        aCookie = self.generateCookie(address, rKey)
        hObj.cookieLength = len(aCookie)
        serialize.extend(uint8(hObj.cookieLength))
        hObj.cookie = aCookie
        serialize.extend(hObj.cookie)
        socket.sendto(serialize, address)
        del serialize

    def serverHello(self, rObj, hObj, socket, address):
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 1
        serialize.extend(uint48(rObj.seqNumber))
        serialize.extend(uint16(69))
        hObj.handShakeType = server_hello
        serialize.extend(uint8(hObj.handShakeType))
        serialize.extend(uint24(57))
        hObj.msgSequence = 1
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        serialize.extend(uint24(57))
        serialize.extend(uint16(hObj.version))
        serialize.extend(serverRandom)
        serialize.extend(uint8(0))
        hObj.cipherSuites = cipherSupport
        serialize.extend(uint16(hObj.cipherSuites))

        serialize.extend(uint8(0))

        serialize.extend(uint16(0))
        '''

        serialize.extend(uint16(65281))
        serialize.extend(uint16(1))
        serialize.extend(uint8(0))

        serialize.extend(uint16(35))
        serialize.extend(uint16(0))

        serialize.extend(uint16(15))
        serialize.extend(uint16(1))
        serialize.extend(uint8(1))
        '''
        socket.sendto(serialize, address)
        del serialize

    def serverHelloDone(self, rObj, hObj, socket, address):
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 3
        serialize.extend(uint48(rObj.seqNumber))
        serialize.extend(uint16(12))
        hObj.handShakeType = server_hello_done
        serialize.extend(uint8(hObj.handShakeType))
        serialize.extend(uint24(0))
        hObj.msgSequence = 3
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        serialize.extend(uint24(0))
        socket.sendto(serialize, address)
        del serialize

    def createCertificate(self, hObj):
        with open("certificate.pem",'r') as f:
            data=f.read()

        REX_PEM = re.compile("\-+BEGIN [\d\w\s\.]+\-+(.*?)\-+END [\d\w\s\.]+\-+",re.MULTILINE|re.DOTALL)
        pem = REX_PEM.search(data)
        if not pem:
            raise Exception("not in pem format")

        pem = pem.group(1)
        pem = pem.replace("\n","")
        hObj.certificate = pem.decode("base64")
        hObj.certificateLength = len(hObj.certificate)


    def serverCertificate(self, rObj, hObj, socket, address):
        self.createCertificate(hObj)
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 2
        serialize.extend(uint48(rObj.seqNumber))
        serialize.extend(uint16(hObj.certificateLength + 18))
        hObj.handShakeType = certificate
        serialize.extend(uint8(hObj.handShakeType))
        serialize.extend(uint24(hObj.certificateLength + 6))
        serialize.extend(uint16(hObj.msgSequence))
        serialize.extend(uint24(hObj.fragmentOffset))
        hObj.fragmentLength = hObj.certificateLength + 6
        serialize.extend(uint24(hObj.fragmentLength))
        serialize.extend(uint24(hObj.certificateLength + 3))
        serialize.extend(uint24(hObj.certificateLength))
        serialize.extend(hObj.certificate)
        socket.sendto(serialize, address)
        del serialize

    def decryptKeyExchange(self, hObj, aKey):
        with open("key.pem",'r') as f:
            data=f.read()

        privateKey = load_pem_private_key(data, password=None, backend=default_backend())
        secKey = privateKey.decrypt(
            aKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        hObj.preMasterSecret = secKey
        print("Pre-MasterSecret received from client....")

    def cipherSpecChange(self, rObj, socket, address):
        serialize = bytearray()
        serialize.extend(uint8(change_cipher_spec))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 3
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = 1
        serialize.extend(uint16(rObj.length))
        changeCipherSpecMessage = 1
        serialize.extend(uint8(changeCipherSpecMessage))
        socket.sendto(serialize, address)
        del serialize

    def generateMasterSecret(self, hObj):
        label = bytearray("master secret")
        seed = hObj.clientRandom + serverRandom

        res = b""
        req_len = 48
        hash_len = 32
        n = req_len + hash_len - 1

        labelAndSeed = bytes_encode(label)
        labelAndSeed += bytes_encode(seed)

        a = hmac.new(hObj.preMasterSecret, labelAndSeed, hashlib.sha256).digest()

        while n > 0:
            res += hmac.new(hObj.preMasterSecret, bytes_encode(a + labelAndSeed), hashlib.sha256).digest()
            a = hmac.new(hObj.preMasterSecret, bytes_encode(a), hashlib.sha256).digest()
            n -= 1

        return res[:req_len]

    def encryptedHandshakeMessage(self, rObj, hObj, socket, address):
        serialize = bytearray()
        serialize.extend(uint8(rObj.contentType))
        serialize.extend(uint16(rObj.version))
        rObj.epoch = 1
        serialize.extend(uint16(rObj.epoch))
        rObj.seqNumber = 0
        serialize.extend(uint48(rObj.seqNumber))
        bMaster = bytearray("server finished")
        masterSec = self.generateMasterSecret(hObj)
        hObj.masterSecret = masterSec
        #print("hhhh", masterSecret)
        aVal = hmac.new(masterSec, bMaster, hashlib.sha256).digest()
        rObj.length = len(aVal)
        serialize.extend(uint16(rObj.length))
        serialize.extend(aVal)
        socket.sendto(serialize, address)
        del serialize

    def additionalKeyFromMasterSecret(self, hObj):
        masterSecretVal = hObj.masterSecret
        label = bytearray("key expansion")
        seed = hObj.clientRandom + serverRandom
        res = b""
        req_len = 32
        hash_len = 32
        n = req_len + hash_len - 1
        labelAndSeed = bytes_encode(label)
        labelAndSeed += bytes_encode(seed)
        a = hmac.new(masterSecretVal, labelAndSeed, hashlib.sha256).digest()

        while n > 0:
            res += hmac.new(masterSecretVal, bytes_encode(a + labelAndSeed), hashlib.sha256).digest()
            a = hmac.new(masterSecretVal, bytes_encode(a), hashlib.sha256).digest()
            n -= 1

        return res

    def getKeyFromMaster(self, hObj, kObj):
        key_block = self.additionalKeyFromMasterSecret(hObj)
        kObj.client_write_MAC_key = key_block[0:32]
        kObj.server_write_MAC_key = key_block[32:64]
        kObj.client_write_key  = key_block[64:80]
        kObj.server_write_key = key_block[80:96]
        kObj.client_write_IV = key_block[96:100]
        kObj.server_write_IV = key_block[100:104]

    def decryptMessage(self, rObj, hObj, kObj, sock, address, aVal):
        iv = kObj.client_write_IV
        tag = aVal[0:16]
        ciphertext = aVal[16:]
        decryptor = Cipher(
            algorithms.AES(kObj.client_write_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(kObj.client_write_MAC_key)

        decryptedVal = decryptor.update(ciphertext) + decryptor.finalize()
        print("decryptedVal", decryptedVal)
        self.replyMessageToClient(rObj, kObj, decryptedVal, sock, address)

    def replyMessageToClient(self, rObj, kObj, aVal, socket, address):
        replyMsg = "Back to you: " + aVal + " - " + "hi client from server"
        iv = kObj.server_write_IV
        encryptor = Cipher(
            algorithms.AES(kObj.server_write_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(kObj.server_write_MAC_key)
        ciphertext = encryptor.update(replyMsg) + encryptor.finalize()
        serialize = bytearray()
        serialize.extend(uint8(application_data))
        serialize.extend(uint16(rObj.version))
        serialize.extend(uint16(1))
        rObj.seqNumber = 2
        serialize.extend(uint48(rObj.seqNumber))
        rObj.length = len(ciphertext) + len(encryptor.tag)
        serialize.extend(uint16(rObj.length))
        serialize.extend(encryptor.tag)
        serialize.extend(ciphertext)
        socket.sendto(serialize, address)
        del serialize

    def fetchRequest(self, sock, reqType, addr, key, addVal):
        if reqType == client_hello:
            if addVal is None:
                self.helloVerifyRequest(self.recObj, self.handObj, sock, addr, key)
            else:
                self.verifyCookie(addVal, addr, key)
                self.serverHello(self.recObj, self.handObj, sock, addr)
                self.serverCertificate(self.recObj, self.handObj, sock, addr)
                self.serverHelloDone(self.recObj, self.handObj, sock, addr)
        elif reqType == client_key_exchange:
            self.decryptKeyExchange(self.handObj, addVal)
            self.cipherSpecChange(self.recObj, sock, addr)
            self.encryptedHandshakeMessage(self.recObj, self.handObj, sock, addr)
            self.getKeyFromMaster(self.handObj, self.keyObj)
        elif reqType == application_data:
            self.decryptMessage(self.recObj, self.handObj, self.keyObj, sock, addr, addVal)

    def updateRandom(self, ranVal):
        self.handObj.clientRandom = ranVal

def main():
    rKey = urandom(16)
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPServerSocket.settimeout(1)
    UDPServerSocket.bind((serverIP, serverPort))
    dtlsObj = DTLS()
    seqFlag = True
    seq = hello_verify_request
    while(True):
        try:
            dataFromClient = UDPServerSocket.recvfrom(bufferSize)
        except socket.timeout:
            continue
        else:
            data = dataFromClient[0]
            address = dataFromClient[1]
            if seqFlag:
                seq = (int(data[13:14].encode('hex'), 16))
            else:
                seq = (int(data[0:1].encode('hex'), 16))
            #print("ll:", data, seq)
            if seq == client_hello:
                cookieLen = (int(data[60:61].encode('hex'), 16))
                if cookieLen == 0:
                    dtlsObj.updateRandom(data[27:59])
                    dtlsObj.fetchRequest(UDPServerSocket, seq, address, rKey, None)
                else:
                    adVal = data[61:77]
                    dtlsObj.fetchRequest(UDPServerSocket, seq, address, rKey, adVal)
                    clientCipher = [(int(data[79:81].encode('hex'), 16))]
                    clientCipher.append((int(data[81:83].encode('hex'), 16)))
                    if cipherSupport not in clientCipher:
                        raise Exception("Handshake Failure alert...not have acceptable set of algorithms")
            elif seq == client_key_exchange:
                print(" Client key received....")
                adVal = data[27:283]
                dtlsObj.fetchRequest(UDPServerSocket, seq, address, None, adVal)
                seqFlag = False
            elif seq == application_data:
                adVal = data[13:]
                dtlsObj.fetchRequest(UDPServerSocket, seq, address, None, adVal)


if __name__ == "__main__":
    main()