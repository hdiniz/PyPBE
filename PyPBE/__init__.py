import os
from hashlib import md5
from base64 import (b64encode, b64decode)
from Crypto.Cipher import DES, DES3

class PBEWithMD5AndDES():

    def __init__(self, pw, iterations):
        self.salt = os.urandom(8)
        (self.key, self.iv) = self.pkcs5(
                self.salt, pw.encode('utf-8'), iterations)

    def pad(self, data):
        n = 8 - (len(data) % 8)
        if n == 0:
            return data + chr(8) * 8
        else:
            return data + chr(n) * n

    def unpad(self, data):
        n = data[-1]
        return data[:-n]

    def encrypt(self, data):
        cipher = DES.new(self.key, DES.MODE_CBC, IV=self.iv)
        return b64encode(
            self.salt + cipher.encrypt(self.pad(data))
        ).decode()

    def decrypt(self, data):
        cipher = DES.new(self.key, DES.MODE_CBC, IV=self.iv)
        ciphered_txt = b64decode(data)
        ciphered_txt = ciphered_txt[8:]
        return self.unpad(
            cipher.decrypt(ciphered_txt)
        ).decode()

    def pkcs5(self, salt, pw, iterations):
        x = pw + salt
        for i in range(iterations):
            x = md5(x).digest()
        return (x[:8], x[8:])
