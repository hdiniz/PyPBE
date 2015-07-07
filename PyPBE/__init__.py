from hashlib import md5
from base64 import (b64encode, b64decode)
from Crypto.Cipher import DES, DES3

class PBECipher(object):
    def pad(self, data):
        # pkcs5 padding
        n = 8 - (len(data) % 8)
        if n == 0:
            return data + chr(8) * 8
        else:
            return data + chr(n) * n

    def unpad(self, data):
        # remove pkcs5 padding
        n = ord(data[-1])
        return data[:-n]

    def encrypt(self, data):
        return self.cipher.encrypt(self.pad(data))

    def decrypt(self, data):
        return self.unpad(self.cipher.decrypt(data))

class PBEWithMD5AndDES(PBECipher):
    def __init__(self, salt, pw, iterations):
        self.pkcs5(salt, pw, iterations)
        self.cipher = DES.new(self.key, DES.MODE_CBC, IV=self.iv)

    def pkcs5(self, salt, pw, iterations):
        x = pw + salt
        for i in range(iterations):
            x = md5(x).digest() 

        self.key = x[:8]
        self.iv = x[8:]

class PBEWithMD5AndTripleDES(PBECipher):
    def __init__(self, salt, pw, iterations):
        self.pkcs5(salt, pw, iterations)
        self.cipher = DES3.new(self.key, DES3.MODE_CBC, IV=self.iv)

    def pkcs5(self, salt, pw, iterations):
        a = salt[:4]
        b = salt[4:]
        if a == b:
            a = a[::-1]
        for i in range(iterations):
            a = md5(a+pw).digest() 
            b = md5(b+pw).digest() 

        self.key = a + b[:8]
        self.iv = b[8:]

