import unittest
import binascii
import md5_crypt

class TestMD5CryptAlgorithm(unittest.TestCase):
    # input data
    password = b"aaa123"
    salt = b"qwertyui"
    magic = b"$1$"
    solution = md5_crypt.MD5CryptAlgorithm()

    # get_alternate test case
    def test_alternate(self):
        # raw expected answer
        expected = "\x9a\x35\xf9\xd7\xfe\xf4\x76\xae\x49\x61\x5f\x4a\xfb\x17\x1c\x17"
        # convert to hex string without \x prefix
        expected = ''.join('%02x' % ord(c) for c in expected)
        
        self.assertEqual(self.solution.get_alternate(self.password, self.salt), expected)

    # get_intermediate test case
    def test_intermediate(self):
        # raw expected answer
        expected = "\x2b\xea\x6b\x33\xea\xec\xe8\xab\x8a\xa3\x15\xd1\x0f\xd6\x8c\x34"
        # convert to hex string without \x prefix
        expected = ''.join('%02x' % ord(c) for c in expected)

        self.assertEqual(self.solution.get_intermediate(self.password, self.salt, self.magic), expected)

    # loop test case
    def test_loop(self):
        # raw expected answer 
        expected = b"\x41\x26\x7a\x0d\x63\x7a\xc6\x04\x98\x5b\x8e\x6e\xd7\x5f\x67\x45"
        intermediate = b"\x2b\xea\x6b\x33\xea\xec\xe8\xab\x8a\xa3\x15\xd1\x0f\xd6\x8c\x34"
        self.assertEqual(binascii.hexlify(expected), binascii.hexlify(self.solution.loop(intermediate, self.password, self.salt)))

    # get_bytes test case
    def test_get_bytes(self):
        # raw expected answer 
        expected = b"\x6e\x63\x8e\x7a\x0d\x5b\x45\x7a\x98\x67\x26\x04\x5f\x41\xc6\xd7"
        intermediate = b"\x41\x26\x7a\x0d\x63\x7a\xc6\x04\x98\x5b\x8e\x6e\xd7\x5f\x67\x45"
        self.assertEqual(expected, self.solution.get_bytes(intermediate))

    # hash test case
    def test_hash(self):
        expected = "$1$qwertyui$LPQETFU7bVdS3hJ1utsMi/"
        self.assertEqual(expected, self.solution.hash(self.password, self.salt))


if __name__ == "__main__":
    unittest.main()
