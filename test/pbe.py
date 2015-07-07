import unittest
from base64 import (b64encode, b64decode)
import PyPBE

class TestPBEWithMD5AndDES(unittest.TestCase):
    salt = "\xc7\x73\x21\x8c\x7e\xc8\xee\x99"
    password = 'test'
    data = 'some_data'
    encrypted = '+nTmgh2tJk3X4myY0g7J7w=='
    iterations = 20
    
    def test_encode(self):
        tmp = PyPBE.PBEWithMD5AndDES(self.salt, self.password, self.iterations).encrypt(self.data)
        self.assertEqual(self.encrypted, b64encode(tmp))

    def test_decode(self):
        tmp = b64decode(self.encrypted)
        self.assertEqual(self.data, PyPBE.PBEWithMD5AndDES(self.salt, self.password, self.iterations).decrypt(tmp))

class TestPBEWithMD5AndTripleDES(unittest.TestCase):
    salt = "\xc7\x73\x21\x8c\x7e\xc8\xee\x99"
    password = 'test'
    data = 'some_data'
    encrypted = 'TM+Ij7MBrzcBBDOaotfj7Q=='
    iterations = 20
    
    def test_encode(self):
        tmp = PyPBE.PBEWithMD5AndTripleDES(self.salt, self.password, self.iterations).encrypt(self.data)
        self.assertEqual(self.encrypted, b64encode(tmp))

    def test_decode(self):
        tmp = b64decode(self.encrypted)
        self.assertEqual(self.data, PyPBE.PBEWithMD5AndTripleDES(self.salt, self.password, self.iterations).decrypt(tmp))

if __name__ == '__main__':
    unittest.main()
