from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import os


def generate_parameters():
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )
    return parameters


def generate_private_key(parameters):
    private_key = parameters.generate_private_key()
    return private_key


def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key


def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key


def derive_key(shared_key, salt=None, length=32):
    if salt is None:
        salt = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(shared_key)
    return key, salt


def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_message(key, ciphertext):
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    encrypted_message = ciphertext[12:]
    return aesgcm.decrypt(nonce, encrypted_message, None)


if __name__ == "__main__":
    # example of excange

    num_participants = 5  # number of participants
    participants = []

    # generate parameters
    parameters = generate_parameters()

    # generate private and public keys for each participant
    for i in range(num_participants):
        private_key = generate_private_key(parameters)
        public_key = generate_public_key(private_key)
        participants.append((private_key, public_key))

    # first participant generates shared keys with all other participants
    shared_keys = []
    for i in range(1, num_participants):
        shared_key = generate_shared_key(participants[0][0], participants[i][1])
        shared_keys.append(shared_key)

    # all other participants generate shared key with first participant
    shared_keys_others_to_first = []
    for i in range(1, num_participants):
        shared_key = generate_shared_key(participants[i][0], participants[0][1])
        shared_keys_others_to_first.append(shared_key)

    # derive symmetric keys
    symmetric_keys = []
    salts = []
    for shared_key in shared_keys:
        symmetric_key, salt = derive_key(shared_key)
        symmetric_keys.append(symmetric_key)
        salts.append(salt)

    # derive symmetric keys for others
    symmetric_keys_others_to_first = []
    salts_others_others_to_first = []
    for i, shared_key in enumerate(shared_keys_others_to_first):
        symmetric_key, salt = derive_key(shared_key, salt=salts[i])
        symmetric_keys_others_to_first.append(symmetric_key)
        salts_others_others_to_first.append(salt)

    # first participant generates a random key K
    K = os.urandom(32)

    # first participant encrypts K with each symmetric key and broadcasts them
    encrypted_keys = []
    for symmetric_key in symmetric_keys:
        encrypted_K = encrypt_message(symmetric_key, K)
        encrypted_keys.append(encrypted_K)

    # each participant decrypts their own encrypted version of K
    for i in range(1, num_participants):
        decrypted_K = decrypt_message(
            symmetric_keys_others_to_first[i - 1], encrypted_keys[i - 1]
        )
        assert decrypted_K == K

    print("All participants have successfully derived the shared key K.")
