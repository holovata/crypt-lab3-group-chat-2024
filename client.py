import base64
import datetime
import random
import string
import asyncio
import websockets
import json
import diffie_hellman as dh

from controller import EncryptionController
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


encryption_ctrl = None
user = None

WAITING = "waiting"
ACTIVE = "active"
KEY_SETUP_PHASE1 = "setup1"
KEY_SETUP_PHASE2 = "setup2"
state = WAITING

# Дані для першого користувача
pub_keys = {}  # Публічні ключі учасників
shared_keys = {}  # Спільні ключі учасників
sym_keys = {}  # Симетричні ключі учасників
salts = {}  # Солі учасників

my_sym_key = None  # Власний симетричний ключ
my_salt = None  # Власна сіль

SHARED_KEY = None  # Загальний ключ

participant_count = 0  # Кількість учасників
processed_count = 0  # Лічильник оброблених учасників

# Параметри для алгоритму Диффі-Хеллмана
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = DHParameterNumbers(p, g)
parameters = params_numbers.parameters(default_backend())

# Генерація приватного та публічного ключів для користувача
priv_key = dh.generate_private_key(parameters)
pub_key = dh.generate_public_key(priv_key)


# Функція для серіалізації публічного ключа у строку
def serialize_pub_key(pub_key):
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pub_bytes).decode("utf-8")


# Функція для десеріалізації строки у публічний ключ
def deserialize_pub_key(pub_key_str):
    pub_bytes = base64.b64decode(pub_key_str.encode("utf-8"))
    return serialization.load_pem_public_key(pub_bytes)


# Функція для генерації юзернейму
def create_username():
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"user_{timestamp}_{random_string}"


'''
async def send_user_msg(ws):
    global encryption_ctrl, state

    while state == ACTIVE:
        message = await asyncio.to_thread(input, "Введіть повідомлення: ")
        message_json = encryption_ctrl.create_message_json(
            message, user["username"]
        )
        await ws.send(json.dumps(message_json))'''


# Функція для обробки підключення до сервера та відправки ідентифікаційної інформації
async def connect_to_server(ws):
    global user
    user = {
        "username": create_username(),
        "pub_key": serialize_pub_key(pub_key),
    }
    await ws.send(json.dumps(user))


# Функція для обробки повідомлень від сервера
async def handle_messages(ws):
    async for message in ws:
        data = json.loads(message)
        print(data)
        if "error" in data:
            print(data["error"])
        elif "state" in data:
            global state
            state = data["state"]
            print(f"Перехід до стану {state}.")
            if state == KEY_SETUP_PHASE1:
                await handle_key_setup1(ws, data)
            elif state == KEY_SETUP_PHASE2:
                await handle_key_setup2(ws, data)
            elif state == ACTIVE:
                await handle_active_state(ws, data)


# Функція для обробки стану KEY_SETUP_PHASE1
async def handle_key_setup1(ws, data):
    global participant_count
    participant_count = data["participant_count"]
    await ws.send(
        json.dumps({"pub_key": serialize_pub_key(pub_key)})
    )


# Функція для обробки стану KEY_SETUP_PHASE2
async def handle_key_setup2(ws, data):
    global my_sym_key, my_salt, SHARED_KEY, encryption_ctrl
    first_pub_key = deserialize_pub_key(
        data["first_pub_key"]
    )
    shared_secret = dh.generate_shared_key(
        priv_key, first_pub_key
    )
    my_sym_key, my_salt = dh.derive_key(shared_secret)
    dec_key = dh.decrypt_message(
        my_sym_key,
        base64.b64decode(data["encrypted_K"].encode("utf-8")),
    )

    SHARED_KEY = dec_key
    encryption_ctrl = EncryptionController(SHARED_KEY)
    print(SHARED_KEY)
    print("Encryption Controller:")
    print(encryption_ctrl)

    await ws.send(json.dumps({"state": ACTIVE}))


# Функція для обробки стану ACTIVE
async def handle_active_state(ws, data):
    print("Перехід до активного стану.")
    messages = [
        "hi",
        "hello",
        "how are you?",
        "i'm tired",
    ]
    for message in messages:
        message_json = encryption_ctrl.create_message_json(
            message, user["username"]
        )
        await ws.send(json.dumps(message_json))


# Основна функція для підключення до сервера та обробки повідомлень
async def main_send_messages():
    uri = "ws://localhost:8090"
    async with websockets.connect(uri) as ws:
        await connect_to_server(ws)
        await handle_messages(ws)

if __name__ == "__main__":
    asyncio.run(main_send_messages())
