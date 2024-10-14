from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padding2
import os
from gmssl import sm4
from gmssl import sm3, func

class S_SM3:
    def __init__(self):
        pass

    def Encryption(self, plaintext):
        # SM3 哈希计算
        hash_result = sm3.sm3_hash(func.bytes_to_list(plaintext))
        return hash_result

    def Decryption(self, ciphertext):
        raise NotImplementedError("SM3 是不可逆的哈希函数，不能解密。")

class S_SM4:
    def __init__(self):
        self.sm4 = sm4.CryptSM4()
        self.key = None

    def SetKey(self, key):
        self.key = key
        self.sm4.set_key(self.key, sm4.SM4_ENCRYPT)  # 初始化加密

    def Encryption(self, plaintext):
        # 加密操作
        self.sm4.set_key(self.key, sm4.SM4_ENCRYPT)
        ciphertext = self.sm4.crypt_ecb(plaintext)
        return ciphertext

    def Decryption(self, ciphertext):
        # 解密操作
        self.sm4.set_key(self.key, sm4.SM4_DECRYPT)
        plaintext = self.sm4.crypt_ecb(ciphertext)
        return plaintext

    
# ECC加密类
class S_ECC:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    def sign(self, message):
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, signature, message):
        public_key = self.private_key.public_key()
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False


# SM2加密类（基于ECC）
class S_SM2:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def sign(self, message):
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, signature, message):
        public_key = self.private_key.public_key()
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False


# MD5哈希类
class S_MD5:
    def __init__(self):
        pass

    def Encryption(self, plaintext):
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        digest.update(plaintext)
        return digest.finalize()

    def Decryption(self, ciphertext):
        raise NotImplementedError("MD5 是不可逆的哈希函数，不能解密。")
