import socket
import threading
from user_auth import init_db, register_user, authenticate_user

HOST = '192.168.25.235'
PORT = 5000

init_db()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = {}         # {socket: username}
user_sockets = {}    # {username: socket}
lock = threading.Lock()

def handle_file_transfers():
    file_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_server.bind((HOST, PORT + 1))
    file_server.listen()
    
    while True:
        client, addr = file_server.accept()
        threading.Thread(target=handle_file_transfer, args=(client,), daemon=True).start()

def handle_file_transfer(client):
    try:
        # Get sender and receiver info
        header = client.recv(1024).decode()
        sender, receiver = header.strip().split('\n')
        
        with lock:
            receiver_socket = user_sockets.get(receiver)
            
        if receiver_socket:
            # Notify receiver that file data is coming
            receiver_socket.send(f"/file_data {sender}".encode())
            
            # Forward all data from sender to receiver
            with lock:
                receiver_ip = receiver_socket.getpeername()[0]
            
            # Send recipient IP to sender
            client.send(f"{receiver_ip}".encode())
        else:
            client.send("❌ User offline".encode())
    except Exception as e:
        print(f"❌ Error handling file transfer: {e}")
    finally:
        client.close()
def broadcast_user_list():
    with lock:
        users = [u for u in user_sockets.keys() if u.strip()]
    print("📤 Broadcasting user list:", users)
    user_msg = "/userlist\n" + "\n".join(users)
    broadcast(user_msg)


def broadcast(message, exclude_client=None):
    for client in clients:
        try:
            if client != exclude_client:
                client.send(message.encode('utf-8'))
        except:
            pass


def handle(client):
    try:
        username = clients[client]
        client.send("Connected! Welcome to the chat.".encode())  # ✅ send welcome here
        broadcast(f"🟢 {username} joined the chat.")
        while True:
            message = client.recv(1024).decode()
            print(f"📩 Received from {username}: {message}")
            if not message:
                break

            if message.strip() == "/users":
                with lock:
                    user_list = "\n".join(user_sockets.keys())
                client.send(f"/userlist\n{user_list}".encode())

            elif message.startswith("/call"):
                print(f"📞 Call request from {username}: {message}")
                _, target_nick = message.split()
                with lock:
                    target_socket = user_sockets.get(target_nick)
                if target_socket:
                    caller_ip = client.getpeername()[0]  # IP of the caller
                    target_socket.send(f"/call_from {clients[client]} {caller_ip}".encode())
                else:
                    client.send(f"❌ User {target_nick} not found.".encode())

            elif message.startswith("/room_file"):
                # User is offering a file to the room
                _, file_name, file_size = message.split(maxsplit=2)
                broadcast(f"{username}: /room_file {file_name} {file_size}")

            elif message.startswith("/get_room_file"):
                # User wants to download a file offered in the room
                _, target, file_name = message.split(maxsplit=2)
                with lock:
                    target_socket = user_sockets.get(target)
                if target_socket:
                    target_socket.send(f"/get_room_file_request {username} {file_name}".encode())
                else:
                    client.send(f"❌ User {target} is offline or has disconnected.".encode())




            elif message.startswith("/file_request"):
                _, target, file_name, file_size = message.split(maxsplit=3)
                with lock:
                    target_socket = user_sockets.get(target)
                if target_socket:
                    target_socket.send(f"/file_request {username} {file_name} {file_size}".encode())
                else:
                    client.send(f"❌ User {target} is offline.".encode())

            elif message.startswith("/file_accept"):
                _, sender, file_name = message.split(maxsplit=2)
                with lock:
                    sender_socket = user_sockets.get(sender)
                if sender_socket:
                    sender_socket.send(f"/file_accept {username} {file_name}".encode())
                else:
                    client.send(f"❌ User {sender} is offline.".encode())

            elif message.startswith("/file_reject"):
                _, sender, file_name = message.split(maxsplit=2)
                with lock:
                    sender_socket = user_sockets.get(sender)
                if sender_socket:
                    sender_socket.send(f"/file_reject {username} {file_name}".encode())


            elif message.startswith("/msg"):
                try:
                    _, target, *msg_parts = message.split()
                    target = target.strip()
                    msg = " ".join(msg_parts)
                    with lock:
                        target_socket = user_sockets.get(target)
                    if target_socket:
                        target_socket.send(f"[PM from {username}]: {msg}".encode())
                        client.send(f"[PM to {target}]: {msg}".encode())
                    else:
                        client.send("❌ User not found.".encode())
                except Exception as e:
                    client.send(f"❌ Failed to send message: {str(e)}".encode())
            else:
                broadcast(f"{username}: {message}")

    except Exception as e:
        print(f"❌ Error handling {clients.get(client)}: {e}")
    finally:
        with lock:
            username = clients.pop(client, None)
            if username:
                user_sockets.pop(username, None)
                broadcast(f"🔴 {username} left the chat.")
                broadcast_user_list()
        client.close()


def receive():
    print(f"Server started at {HOST}:{PORT}")
    file_transfer_thread = threading.Thread(target=handle_file_transfers, daemon=True)
    file_transfer_thread.start()
    while True:
        client, addr = server.accept()
        print(f"🔌 Connection from {addr}")
        nickname_data = b""
        while not nickname_data.endswith(b"\n"):
            nickname_data += client.recv(1)
        nickname = nickname_data.decode().strip()
        print(f"👤 Nickname received: {nickname}")

        with lock:
            clients[client] = nickname
            user_sockets[nickname] = client
            
        broadcast_user_list()
        threading.Thread(target=handle, args=(client,), daemon=True).start()

receive()
