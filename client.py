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

encryptionController = None

user_info = None

lobbyState = "lobby"
preparingOneState = "preparing_1"
preparingTwoState = "preparing_2"
chatState = "chat"

current_state = lobbyState

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = DHParameterNumbers(p, g)
parameters = params_numbers.parameters(default_backend())

private_key = dh.generate_private_key(parameters)
public_key = dh.generate_public_key(private_key)

number_of_participants = 0
processed_number_of_participants = 0

# First user data
participants_public_keys = {}
participants_shared_keys = {}
participants_symmetric_keys = {}
participants_salts = {}

# Non-first user data
own_symmetric_key = None
own_salt = None

KEY = None


def serialize_public_key(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_bytes).decode("utf-8")


def deserialize_public_key(public_key_str):
    public_bytes = base64.b64decode(public_key_str.encode("utf-8"))
    return serialization.load_pem_public_key(public_bytes)


async def send_user_messages(websocket):
    global encryptionController, current_state

    while current_state == chatState:
        message = await asyncio.to_thread(input, "Enter message: ")
        message_json = encryptionController.create_message_json(
            message, user_info["username"]
        )
        await websocket.send(json.dumps(message_json))


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
        # Send identifying information upon connection
        user_info = {
            "username": "bob" + str(os.urandom(4).hex()),
            "public_key": serialize_public_key(public_key),
        }
        await websocket.send(json.dumps(user_info))

        async for message in websocket:
            data = json.loads(message)
            print(data)
            if "error" in data:
                print(data["error"])
            elif "state" in data:
                global current_state
                current_state = data["state"]
                print(f"State transitioned to: {current_state}")
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
                    print("Chat state reached")
                    messageList = [
                        "Hello, World!",
                        "This is a test message",
                        "Goodbye!",
                    ]
                    for message in messageList:
                        message_json = encryptionController.create_message_json(
                            message, user_info["username"]
                        )
                        await websocket.send(json.dumps(message_json))
                    # asyncio.create_task(send_user_messages(websocket))

            elif current_state == preparingOneState:
                # First user flow:
                participants_public_keys[data["username"]] = deserialize_public_key(
                    data["public_key"]
                )
                print("Participants public keys:")
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
                print("Encrypted Message")
                print(encrypted_message)
                decrypted_message = encryptionController.decrypt(iv, encrypted_message)
                print("Decrypted Message")
                print(decrypted_message)


if __name__ == "__main__":
    asyncio.run(send_messages())
