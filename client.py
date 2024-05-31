import os
import json
import base64
import datetime
import random
import string
import asyncio
import websockets

import diffie_hellman as dh

from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from controller import EncryptionController

encryptionController = None
user = None

# Константи для станів
WAITING = "WAITING"
ACTIVE = "ACTIVE"
KEY_SETUP_PHASE1 = "KEY_SETUP_PHASE1"
KEY_SETUP_PHASE2 = "KEY_SETUP_PHASE2"

current_state = WAITING

# Параметри для алгоритму Диффі-Хеллмана
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = DHParameterNumbers(p, g)
parameters = params_numbers.parameters(default_backend())

# Генерація приватного та публічного ключів
private_key = dh.generate_private_key(parameters)
public_key = dh.generate_public_key(private_key)

participants_number = 0
processed_participants_number = 0

# Дані для першого користувача
pub_keys = {}
shared_keys = {}
sym_keys = {}
salts = {}

# Дані для непершого користувача
my_sym_key = None
my_salt = None

shared_key = None


# Функція для серіалізації публічного ключа в рядок
def serialize_key(pub_key):
    public_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_bytes).decode("utf-8")


# Функція для десеріалізації рядка в публічний ключ
def deserialize_key(pub_key_str):
    public_bytes = base64.b64decode(pub_key_str.encode("utf-8"))
    return serialization.load_pem_public_key(public_bytes)


# Функція для генерації унікального імені користувача
def generate_username():
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"user_{timestamp}_{random_str}"


# Основна функція
async def main():
    global pub_keys, shared_keys, sym_keys, salts
    global participants_number, processed_participants_number, my_sym_key, my_salt, shared_key
    global public_key, private_key, encryptionController, user

    uri = "ws://localhost:8090"

    # Підключення до WebSocket
    async with websockets.connect(uri) as websocket:

        # Генерація імені користувача та серіалізація публічного ключа
        user = {
            "username": generate_username(),
            "public_key": serialize_key(public_key),
        }

        # Надсилання інформації користувача серверу
        await websocket.send(json.dumps(user))

        # Обробка повідомлень від сервера
        async for message in websocket:
            data = json.loads(message)
            print(f"Отримано повідомлення - {data}.")

            # Якщо в отриманих даних є помилка
            if "error" in data:
                print(f"Помилка! {data['error']}.")

            # Обробка стану сервера
            elif "state" in data:
                global current_state
                current_state = data["state"]
                print(f"Перехід до стану {current_state}.")

                # Обробка першої фази налаштування ключів
                if current_state == KEY_SETUP_PHASE1:
                    participants_number = data["participants_number"]
                    await websocket.send(json.dumps({"public_key": serialize_key(public_key)}))

                # Обробка другої фази налаштування ключів
                elif current_state == KEY_SETUP_PHASE2:
                    first_user_pub_key = deserialize_key(data["first_user_pub_key"])
                    shared_key = dh.generate_shared_key(private_key, first_user_pub_key)
                    my_sym_key, my_salt = dh.derive_key(shared_key)
                    dec_key = dh.decrypt_message(
                        my_sym_key,
                        base64.b64decode(data["enc_key"].encode("utf-8")),
                    )
                    shared_key = dec_key
                    encryptionController = EncryptionController(shared_key)
                    print(f"Спільний ключ: {shared_key}.")
                    print("Encryption Controller ініціалізовано.")
                    print(encryptionController.key)

                    await websocket.send(json.dumps({"state": ACTIVE}))

                # Обробка активного стану
                if current_state == ACTIVE:
                    print("Перехід до активного стану.")
                    messages = ["Hello, Bob", "Hi, Alice!", "Hey, Eva"]
                    for message in messages:
                        message_json = encryptionController.create_message_json(message, user["username"])
                        await websocket.send(json.dumps(message_json))

            # Обробка повідомлень для першого користувача
            elif current_state == KEY_SETUP_PHASE1:
                pub_keys[data["username"]] = deserialize_key(data["public_key"])
                print("Публічні ключі учасників:")
                print(pub_keys[data["username"]].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode())
                print(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode())
                print(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode())
                shared_keys[data["username"]] = dh.generate_shared_key(private_key, pub_keys[data["username"]])
                sym_keys[data["username"]], salts[data["username"]] = dh.derive_key(shared_keys[data["username"]])
                processed_participants_number += 1

                # Якщо всі учасники оброблені, генерувати спільний ключ та перейти до другої фази
                if processed_participants_number >= participants_number - 1:
                    K = os.urandom(32)
                    shared_key = K
                    encryptionController = EncryptionController(shared_key)
                    print(f"Спільний ключ: {shared_key}")
                    await websocket.send(
                        json.dumps(
                            {
                                "state": KEY_SETUP_PHASE2,
                                "first_user_pub_key": serialize_key(public_key),
                                "enc_key": {
                                    k: base64.b64encode(dh.encrypt_message(v, K)).decode("utf-8")
                                    for k, v in sym_keys.items()
                                },
                            }
                        )
                    )

            # Обробка активного стану
            elif current_state == ACTIVE:
                json_data = json.loads(data)
                encrypted_message = json_data["message"]
                iv = json_data["init_vector"]
                print("Зашифроване повідомлення:")
                print(encrypted_message)
                decrypted_message = encryptionController.decrypt(iv, encrypted_message)
                print("Розшифроване повідомлення:")
                print(decrypted_message)


if __name__ == "__main__":
    asyncio.run(main())