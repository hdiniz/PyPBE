import unittest
from base64 import (b64encode, b64decode)
import PyPBE

class TestPBEWithMD5AndDES(unittest.TestCase):
    password = 'test'
    data = 'some_data'
    iterations = 20

    def test_encode(self):
        cipher = PyPBE.PBEWithMD5AndDES(self.password, self.iterations)
        ciphered_text = cipher.encrypt(self.data)
        self.assertEqual(self.data, cipher.decrypt(ciphered_text))

if __name__ == '__main__':
    unittest.main()
