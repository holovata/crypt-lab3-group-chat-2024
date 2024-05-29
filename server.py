import asyncio
import websockets
import json

connected_users = {}

lobbyState = "lobby"
preparingOneState = "preparing_1"
preparingTwoState = "preparing_2"
chatState = "chat"

current_state = lobbyState

ready_users = 0


async def handler(websocket: websockets.WebSocketServerProtocol, path: str):
    global current_state, ready_users
    try:
        if current_state != lobbyState:
            await websocket.send(
                json.dumps(
                    {
                        "error": f"No new connections allowed, current state is {current_state}"
                    }
                )
            )
            await websocket.close()
            return

        # Receive initial message containing user info
        user_info = await websocket.recv()
        user_info = json.loads(user_info)
        connected_users[websocket] = user_info
        print(f"User connected: {user_info}")

        async for message in websocket:
            data = json.loads(message)
            if current_state == preparingOneState:
                if "state" in data and data["state"] == preparingTwoState:
                    current_state = preparingTwoState
                    encrypted_K = data["encrypted_K"]

                    for user in connected_users:
                        if user != websocket:
                            await user.send(
                                json.dumps(
                                    {
                                        "state": current_state,
                                        "encrypted_K": encrypted_K[
                                            connected_users[user]["username"]
                                        ],
                                        "first_user_public_key": data[
                                            "first_user_public_key"
                                        ],
                                    }
                                )
                            )

                elif "public_key" in data:
                    connected_users[websocket]["public_key"] = data["public_key"]
                    first_user = list(connected_users.keys())[0]
                    if websocket != first_user:
                        print(first_user)
                        await first_user.send(
                            json.dumps(
                                {
                                    "public_key": data["public_key"],
                                    "username": user_info["username"],
                                }
                            )
                        )
            elif current_state == preparingTwoState:
                if "state" in data and data["state"] == chatState:
                    ready_users += 1
                if ready_users >= len(connected_users) - 1:
                    current_state = chatState
                    for user in connected_users:
                        await user.send(json.dumps({"state": current_state}))
            elif current_state == chatState:
                print("Chat state reached")
                print(data)
                await broadcast(json.dumps(data), websocket)

            else:
                await websocket.send(json.dumps({"error": "Chat has not started yet"}))
    except websockets.ConnectionClosed as e:
        print(
            f"Client disconnected: {websocket.remote_address} with code {e.code} and reason: {e.reason}"
        )
    finally:
        if websocket in connected_users:
            print(f"Connection with {connected_users[websocket]} closed")
            del connected_users[websocket]


async def broadcast(message, sender=None):
    if connected_users:  # Check if there are any connected users
        destinations = [
            user.send(message) for user in connected_users if user != sender
        ]
        if destinations:
            await asyncio.wait(destinations)


async def broadcastToEveryoneExceptFirst(message):
    if connected_users:  # Check if there are any connected users
        destinations = [user.send(message) for user in connected_users[1:]]
        if destinations:
            await asyncio.wait(destinations)


async def handle_start_command():
    global current_state
    current_state = preparingOneState
    await broadcast(
        json.dumps(
            {"state": current_state, "number_of_participants": len(connected_users)}
        )
    )


async def terminal_input(stop_event):
    while True:
        command = await asyncio.to_thread(input, "")
        if command.lower() == "start" and current_state == "lobby":
            await handle_start_command()
            print("Transitioning to chat state...")
        elif command.lower() == "stop":
            print("Stopping server...")
            stop_event.set()
            break
        else:
            print(f"Unknown command: {command}")


async def main():
    stop_event = asyncio.Event()
    server = await websockets.serve(handler, "localhost", 8090)
    input_task = asyncio.create_task(terminal_input(stop_event))

    await stop_event.wait()
    server.close()
    await server.wait_closed()
    await input_task


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped by user")
