import binascii
import hashlib
import sys

class MD5CryptAlgorithm:
    # base64 table
    b64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def string_to_hex(self, string: str) -> str:
        return binascii.hexlify(string.encode())

    def get_alternate(self, password: str, salt: str) -> str:
        return hashlib.md5(password + salt + password).hexdigest()

    def get_intermediate(self, password: str, salt: str, magic: str) -> str:
        intermediate = password + magic + salt
        alternate = self.get_alternate(password, salt)
        passwd_length = len(password)

        xalternate = binascii.unhexlify(alternate)
        for i in range(passwd_length, 0, -16):
            intermediate += xalternate[0:16 if i > 16 else i]

        while passwd_length:
            if passwd_length & 1:
                intermediate += chr(0).encode()
            else:
                intermediate += password[0:1]
            
            passwd_length >>= 1

        return hashlib.md5(intermediate).hexdigest()

    def loop(self, intermediate: bytes, password: str, salt: str) -> str:
        for i in range(1000):
            alternate = b""
            if i & 1: alternate += password
            else: alternate += intermediate

            if i % 3: alternate += salt

            if i % 7: alternate += password

            if i & 1: alternate += intermediate
            else: alternate += password

            intermediate = hashlib.md5(alternate).digest()

        return intermediate

    def get_bytes(self, intermediate: bytes) -> bytes:
        response = b""
        idx = [11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12]
        for x in idx:
            response += intermediate[x:x + 1]
        
        return response


    def hash(self, password: bytes, salt: bytes) -> str:
        magic = b"$1$"

        # compute the initial intermediate value
        intermediate = self.get_intermediate(password, salt, magic)

        # loop 
        intermediate = self.loop(binascii.unhexlify(intermediate), password, salt)

        # swap bytes according to the given idx list
        intermediate = self.get_bytes(intermediate)

        # hex to int
        intermediate = int(binascii.hexlify(intermediate), 16)

        # int to base64
        encoded = ""
        for _ in range(22):
            encoded += self.b64[intermediate % 64]
            intermediate //= 64

        return magic.decode() + salt.decode() + '$' + encoded

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Not enough arguments passing in. Please see the usage below:\npython3 md5_crypt.py password salt")
        exit()

    instance = MD5CryptAlgorithm()
    password, salt = sys.argv[1].encode(), sys.argv[2].encode()

    MD5 = instance.hash(password, salt)

    print(MD5)
        






        


        

