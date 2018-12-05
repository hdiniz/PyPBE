import os
from hashlib import md5
from base64 import (b64encode, b64decode)
from Crypto.Cipher import DES, DES3

class PBECipher():
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
        salt = os.urandom(8)
        cipher = self.initCipher(salt)
        return b64encode(
            salt + cipher.encrypt(self.pad(data))
        ).decode()

    def decrypt(self, data):
        ciphered_txt = b64decode(data)
        cipher = self.initCipher(ciphered_txt[:8])
        ciphered_txt = ciphered_txt[8:]
        return self.unpad(
            cipher.decrypt(ciphered_txt)
        ).decode()

    def deriveKeyIv(self, salt):
        return self.pkcs5(
                salt, self.pw.encode('utf-8'), self.iterations)

class PBEWithMD5AndDES(PBECipher):
    def __init__(self, pw, iterations):
        self.pw = pw
        self.iterations = iterations

    def initCipher(self, salt):
        (key, iv) = self.deriveKeyIv(salt)
        return DES.new(key, DES.MODE_CBC, IV=iv)

    def pkcs5(self, salt, pw, iterations):
        x = pw + salt
        for i in range(iterations):
            x = md5(x).digest()
        return (x[:8], x[8:])

class PBEWithMD5AndTripleDES(PBECipher):
    def __init__(self, pw, iterations):
        self.pw = pw
        self.iterations = iterations

    def initCipher(self, salt):
        (key, iv) = self.deriveKeyIv(salt)
        return DES3.new(key, DES3.MODE_CBC, IV=iv)

    def pkcs5(self, salt, pw, iterations):
        a = salt[:4]
        b = salt[4:]
        if a == b:
            a = a[::-1]
        for i in range(iterations):
            a = md5(a+pw).digest()
            b = md5(b+pw).digest()

        return (a + b[:8], b[8:])
