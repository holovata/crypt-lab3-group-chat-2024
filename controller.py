import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
from datetime import datetime


class EncryptionController:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext, mode="AES"):
        if mode == "AES":
            cipher = AES.new(self.key, AES.MODE_CBC)
        elif mode == "3DES":
            cipher = DES3.new(self.key, DES3.MODE_CBC)
        else:
            raise ValueError("Unsupported mode. Use 'AES' or '3DES'.")

        ct_bytes = cipher.encrypt(pad(plaintext.encode(), cipher.block_size))
        init_vector = b64encode(cipher.iv).decode("utf-8")
        ct = b64encode(ct_bytes).decode("utf-8")
        return init_vector, ct

    def decrypt(self, init_vector, ciphertext, mode="AES"):
        init_vector = b64decode(init_vector)
        ct = b64decode(ciphertext)
        if mode == "AES":
            cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        elif mode == "3DES":
            cipher = DES3.new(self.key, DES3.MODE_CBC, init_vector)
        else:
            raise ValueError("Unsupported mode. Use 'AES' or '3DES'.")

        pt = unpad(cipher.decrypt(ct), cipher.block_size).decode("utf-8")
        return pt

    def hmac_sha256(self, message):
        return hmac.new(self.key, message.encode(), hashlib.sha256).hexdigest()

    def create_message_json(self, plaintext, sender=None, time=None, mode="AES"):
        if time is None:
            time = datetime.now().isoformat()

        init_vector, encrypted_message = self.encrypt(plaintext, mode)
        hmac = self.hmac_sha256(encrypted_message)

        message_json = json.dumps(
            {
                "hash": hmac,
                "message": encrypted_message,
                "init_vector": init_vector,
                "sender": sender,
                "timestamp_utc": time,
            },
            indent=4,
        )
        return message_json
