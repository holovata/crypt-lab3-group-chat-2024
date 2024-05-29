import asyncio
import websockets
import json
import diffie_hellman as dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from controller import EncryptionController
import base64
import datetime
import random
import string

encryptionController = None

user_info = None

lobbyState = "lobby"  # Початковий стан лобі
preparingOneState = "preparing_1"  # Стан підготовки першого етапу
preparingTwoState = "preparing_2"  # Стан підготовки другого етапу
chatState = "chat"  # Стан чату

server_state = lobbyState  # Поточний стан системи

# Параметри для алгоритму Диффі-Геллмана
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = DHParameterNumbers(p, g)
parameters = params_numbers.parameters(default_backend())

# Генерація приватного та публічного ключів для користувача
private_key = dh.generate_private_key(parameters)
public_key = dh.generate_public_key(private_key)

number_of_participants = 0  # Кількість учасників
processed_number_of_participants = 0  # Лічильник оброблених учасників

# Дані для першого користувача
participants_public_keys = {}  # Публічні ключі учасників
participants_shared_keys = {}  # Спільні ключі учасників
participants_symmetric_keys = {}  # Симетричні ключі учасників
participants_salts = {}  # Соли учасників

# Дані для не першого користувача
own_symmetric_key = None  # Власний симетричний ключ
own_salt = None  # Власна сіль

KEY = None  # Загальний ключ

# Функція для генерації унікального юзернейму
def generate_username():
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"user_{timestamp}_{random_str}"

# Функція для серіалізації публічного ключа у строку
def serialize_public_key(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_bytes).decode("utf-8")

# Функція для десеріалізації строки у публічний ключ
def deserialize_public_key(public_key_str):
    public_bytes = base64.b64decode(public_key_str.encode("utf-8"))
    return serialization.load_pem_public_key(public_bytes)

# Функція для надсилання повідомлень від користувача у стані чату
async def send_user_messages(websocket):
    global encryptionController, server_state

    while current_state == chatState:
        message = await asyncio.to_thread(input, "Введіть повідомлення: ")
        message_json = encryptionController.create_message_json(
            message, user_info["username"]
        )
        await websocket.send(json.dumps(message_json))

# Функція для підключення до сервера та обробки повідомлень
async def send_messages():
    global \
        participants_public_keys, \
        participants_shared_keys, \
        participants_symmetric_keys, \
        participants_salts, \
        number_of_participants, \
        processed_number_of_participants, \
        own_symmetric_key, \
        own_salt, \
        KEY
    global public_key, private_key, encryptionController, user_info

    uri = "ws://localhost:8090"
    async with websockets.connect(uri) as websocket:
        # Надсилання ідентифікаційної інформації при підключенні
        user_info = {
            "username": generate_username(),
            "public_key": serialize_public_key(public_key),
        }
        await websocket.send(json.dumps(user_info))

        async for message in websocket:
            data = json.loads(message)
            print(data)
            if "error" in data:
                print(data["error"])
            elif "state" in data:
                global server_state
                current_state = data["state"]
                print(f"Перехід до стану: {current_state}")
                if current_state == preparingOneState:
                    number_of_participants = data["number_of_participants"]
                    await websocket.send(
                        json.dumps({"public_key": serialize_public_key(public_key)})
                    )
                elif current_state == preparingTwoState:
                    first_user_public_key = deserialize_public_key(
                        data["first_user_public_key"]
                    )
                    shared_key = dh.generate_shared_key(
                        private_key, first_user_public_key
                    )
                    own_symmetric_key, own_salt = dh.derive_key(shared_key)
                    decrypted_K = dh.decrypt_message(
                        own_symmetric_key,
                        base64.b64decode(data["encrypted_K"].encode("utf-8")),
                    )

                    KEY = decrypted_K
                    encryptionController = EncryptionController(KEY)
                    print(KEY)
                    print("EncryptionController")
                    print(encryptionController)

                    await websocket.send(json.dumps({"state": chatState}))
                if current_state == chatState:
                    print("Досягнуто стану чату")
                    messageList = [
                        "Привіт, світ!",
                        "Це тестове повідомлення",
                        "До побачення!",
                    ]
                    for message in messageList:
                        message_json = encryptionController.create_message_json(
                            message, user_info["username"]
                        )
                        await websocket.send(json.dumps(message_json))
                    # asyncio.create_task(send_user_messages(websocket))

            elif current_state == preparingOneState:
                # Обробка повідомлень для першого користувача:
                participants_public_keys[data["username"]] = deserialize_public_key(
                    data["public_key"]
                )
                print("Публічні ключі учасників:")
                print(participants_public_keys[data["username"]])
                print(public_key)
                print(private_key)
                participants_shared_keys[data["username"]] = dh.generate_shared_key(
                    private_key, participants_public_keys[data["username"]]
                )
                (
                    participants_symmetric_keys[data["username"]],
                    participants_salts[data["username"]],
                ) = dh.derive_key(participants_shared_keys[data["username"]])
                processed_number_of_participants += 1
                if processed_number_of_participants >= number_of_participants - 1:
                    K = os.urandom(32)
                    KEY = K
                    encryptionController = EncryptionController(KEY)
                    print(KEY)
                    await websocket.send(
                        json.dumps(
                            {
                                "state": preparingTwoState,
                                "first_user_public_key": serialize_public_key(
                                    public_key
                                ),
                                "encrypted_K": {
                                    k: base64.b64encode(
                                        (dh.encrypt_message(v, K))
                                    ).decode("utf-8")
                                    for k, v in participants_symmetric_keys.items()
                                },
                            }
                        )
                    )
            elif current_state == chatState:
                json_data = json.loads(data)
                encrypted_message = json_data["message"]
                iv = json_data["init_vector"]
                print("Зашифроване повідомлення")
                print(encrypted_message)
                decrypted_message = encryptionController.decrypt(iv, encrypted_message)
                print("Розшифроване повідомлення")
                print(decrypted_message)


if __name__ == "__main__":
    asyncio.run(send_messages())
