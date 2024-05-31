import json
import asyncio
import websockets

# Константи для різних станів сервера
WAITING = "WAITING"
ACTIVE = "ACTIVE"
KEY_SETUP_PHASE1 = "KEY_SETUP_PHASE1"
KEY_SETUP_PHASE2 = "KEY_SETUP_PHASE2"
current_state = WAITING  # Початковий стан сервера - очікування

connected_users_list = {}  # збереження підключених користувачів
num_ready_users = 0  # Лічильник користувачів, готових до переходу в активний стан


# Функція для запуску додатку (перехід до фази налаштування ключів)
async def run_app():
    global current_state
    current_state = KEY_SETUP_PHASE1  # Змінюємо стан на фазу налаштування ключів
    await broadcast_except_sender(
        json.dumps(
            {"state": current_state, "participants_number": len(connected_users_list)}
        )
    )


# Функція для обробки вводу команд з терміналу
async def process_input(stop_event):
    while True:
        command = await asyncio.to_thread(input, "")  # Чекаємо вводу з терміналу
        if command.lower() == "run" and current_state == "WAITING":
            await run_app()
            print("Перехід до стану підготовки.")
        elif command.lower() == "quit":
            print("Зупинка сервера.")
            stop_event.set()  # Встановлюємо подію для зупинки сервера
            break
        else:
            print(f"Введено невідому команду {command}. Доступні команди: run, quit.")


# Функція для обробки повідомлень від користувачів в чаті
async def process_chat(websocket: websockets.WebSocketServerProtocol, path: str):
    global current_state, num_ready_users
    try:
        # Перевірка стану сервера, якщо не очікує - закриваємо з'єднання
        if current_state != WAITING:
            # Відправляємо повідомлення про заборону нових підключень
            await websocket.send(
                json.dumps(
                    {"error": f"Нові підключення не дозволені. Поточний стан: {current_state}."}
                )
            )
            await websocket.close()  # Закриваємо з'єднання
            return

        # Отримуємо дані користувача
        user = await websocket.recv()  # Читаємо повідомлення від клієнта
        user = json.loads(user)  # Парсимо JSON-повідомлення в словник
        connected_users_list[websocket] = user  # Додаємо користувача до списку підключених
        print(f"Підключено користувача {user}.")

        # Обробляємо повідомлення від користувача
        async for message in websocket:
            data = json.loads(message)  # Парсимо отримане повідомлення
            print(f"Отримане повідомлення - {data}.")

            # Якщо сервер в фазі налаштування ключів (перша фаза)
            if current_state == KEY_SETUP_PHASE1:
                if "state" in data and data["state"] == KEY_SETUP_PHASE2:
                    current_state = KEY_SETUP_PHASE2  # Перехід до другої фази налаштування ключів
                    enc_key = data["enc_key"]  # Отриманий зашифрований ключ

                    # Відправляємо зашифрований ключ іншим користувачам
                    for user in connected_users_list:
                        if user != websocket:
                            await user.send(
                                json.dumps(
                                    {
                                        "state": current_state,
                                        "enc_key": enc_key[connected_users_list[user]["username"]],
                                        "first_user_pub_key": data["first_user_pub_key"],
                                    }
                                )
                            )
                elif "public_key" in data:
                    connected_users_list[websocket]["public_key"] = data["public_key"]  # Зберігаємо публічний ключ користувача
                    first_user = list(connected_users_list.keys())[0]  # Отримуємо першого підключеного користувача
                    if websocket != first_user:
                        await first_user.send(
                            json.dumps(
                                {
                                    "public_key": data["public_key"],
                                    "username": user["username"],
                                }
                            )
                        )
            # Якщо сервер в фазі налаштування ключів (друга фаза)
            elif current_state == KEY_SETUP_PHASE2:
                if "state" in data and data["state"] == ACTIVE:
                    num_ready_users += 1  # Збільшуємо лічильник готових користувачів
                if num_ready_users >= len(connected_users_list) - 1:
                    current_state = ACTIVE  # Перехід до активного стану
                    for user in connected_users_list:
                        await user.send(json.dumps({"state": current_state}))  # Відправляємо повідомлення про активний стан
            # Якщо сервер в активному стані
            elif current_state == ACTIVE:
                await broadcast_except_sender(json.dumps(data), websocket)  # Трансляція повідомлення всім користувачам
            else:
                await websocket.send(json.dumps({"error": "Чат ще не розпочато."}))  # Повідомлення про те, що чат не розпочато
    except websockets.ConnectionClosed as e:
        print(f"Клієнт відключився {websocket.remote_address} з кодом {e.code} через {e.reason}.")
    finally:
        if websocket in connected_users_list:
            print(f"З'єднання з користувачем {connected_users_list[websocket]} закрито.")
            del connected_users_list[websocket]  # Видаляємо користувача зі списку підключених


# Функція для трансляції повідомлень всім користувачам, крім відправника
async def broadcast_except_sender(msg, sender=None):
    if connected_users_list:
        destinations = [user.send(msg) for user in connected_users_list if user != sender]
        if destinations:
            await asyncio.wait(destinations)


# Основна функція для запуску сервера
async def main():
    stop_event = asyncio.Event()
    server = await websockets.serve(process_chat, "localhost", 8090)
    input_task = asyncio.create_task(process_input(stop_event))

    await stop_event.wait()
    server.close()
    await server.wait_closed()
    await input_task

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Сервер зупинено користувачем.")
