import json
import asyncio
import websockets


WAITING = "waiting"             # Початковий стан очікування
ACTIVE = "active"               # Стан активності
KEY_SETUP_PHASE1 = "setup1"     # Стан встановлення спільних ключів шифрування
KEY_SETUP_PHASE2 = "setup2"     # Стан завершення підготовки
state = WAITING

connected_users_list = {}
num_ready_users = 0             # Лічильник готових до переходу на наступний етап користувачів


async def initial_connection(ws, user):
    connected_users_list[ws] = user
    print(f"Підключено користувача {user}.")


async def handle_key_setup1(ws, data):
    global state
    if "state" in data and data["state"] == KEY_SETUP_PHASE2:
        state = KEY_SETUP_PHASE2
        enc_key = data["enc_key"]
        await send_encrypted_keys_to_users(ws, enc_key, data)
    elif "public_key" in data:
        await store_public_key_and_notify_first_user(ws, data)


async def send_encrypted_keys_to_users(ws, enc_key, data):
    for user in connected_users_list:
        if user != ws:
            await user.send(
                json.dumps(
                    {
                        "state": state,
                        "encrypted_key": enc_key[connected_users_list[user]["username"]],
                        "first_user_public_key": data["first_user_public_key"],
                    }
                )
            )


async def store_public_key_and_notify_first_user(ws, data):
    connected_users_list[ws]["public_key"] = data["public_key"]
    first_user = list(connected_users_list.keys())[0]
    if ws != first_user:
        await first_user.send(
            json.dumps(
                {
                    "public_key": data["public_key"],
                    "username": connected_users_list[ws]["username"],
                }
            )
        )


async def handle_key_setup2(ws, data):
    global state, num_ready_users
    if "state" in data and data["state"] == ACTIVE:
        num_ready_users += 1
    if num_ready_users >= len(connected_users_list) - 1:
        state = ACTIVE
        await notify_users_of_active_state()


async def notify_users_of_active_state():
    for user in connected_users_list:
        await user.send(json.dumps({"state": state}))


async def handle_active_state(ws, data):
    print("Перехід до активного стану.")
    print(data)
    await broadcast_except_sender(json.dumps(data), ws)


async def handle_message(ws, msg):
    data = json.loads(msg)
    if state == KEY_SETUP_PHASE1:
        await handle_key_setup1(ws, data)
    elif state == KEY_SETUP_PHASE2:
        await handle_key_setup2(ws, data)
    elif state == ACTIVE:
        await handle_active_state(ws, data)
    else:
        await ws.send(json.dumps({"error": "Чат ще не розпочато."}))


async def handler(ws: websockets.WebSocketServerProtocol, path: str):
    global state
    try:
        if state != WAITING:
            await ws.send(
                json.dumps(
                    {
                        "error": f"Нові підключення не дозволені. Поточний стан: {state}."
                    }
                )
            )
            await ws.close()
            return

        user = await ws.recv()
        user = json.loads(user)
        await initial_connection(ws, user)

        async for msg in ws:
            await handle_message(ws, msg)
    except websockets.ConnectionClosed as e:
        await disconnection(ws, e)
    finally:
        if ws in connected_users_list:
            print(f"З'єднання з користувачем {connected_users_list[ws]} закрито.")
            del connected_users_list[ws]


async def disconnection(ws, e):
    print(
        f"Клієнт відключився: {ws.remote_address} з кодом {e.code} та причиною: {e.reason}."
    )


# Функція для трансляції повідомлення всім користувачам, окрім відправника
async def broadcast_except_sender(msg, sender=None):
    if connected_users_list:  # Перевірка, чи є підключені користувачі
        destinations = [
            user.send(msg) for user in connected_users_list if user != sender
        ]
        if destinations:
            await asyncio.wait(destinations)


# Функція для обробки команди "run" та переходу до стану "setup1"
async def run_command():
    global state
    state = KEY_SETUP_PHASE1
    await broadcast_except_sender(
        json.dumps(
            {"state": state, "number_of_participants": len(connected_users_list)}
        )
    )


# Функція для обробки вводу з терміналу
async def input_from_terminal(stop_event):
    while True:
        command = await asyncio.to_thread(input, "")
        if command.lower() == "run" and state == "waiting":
            await run_command()
            print("Перехід до стану підготовки.")
        elif command.lower() == "quit":
            print("Зупинка сервера.")
            stop_event.set()
            break
        else:
            print(f"Невідома команда: {command}.")


# Основна функція для запуску сервера та обробки вводу
async def main():
    stop_event = asyncio.Event()
    server = await websockets.serve(handler, "localhost", 8090)
    input_task = asyncio.create_task(input_from_terminal(stop_event))

    await stop_event.wait()
    server.close()
    await server.wait_closed()
    await input_task

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Сервер зупинено користувачем.")
