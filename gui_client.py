import sys, socket, threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QTextCursor
from video_stream import start_video_client, start_video_server
import os

class Communicator(QObject):
    message_received = pyqtSignal(str)
    video_call_request = pyqtSignal(str, str)  # For caller, caller_ip


class FileTransferDialog(QDialog):
    def __init__(self, parent, target_user):
        super().__init__(parent)
        self.parent = parent
        self.target_user = target_user
        self.setWindowTitle(f"Send File to {target_user}")
        self.setGeometry(300, 300, 400, 150)
        layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        
        # Buttons
        btn_layout = QHBoxLayout()
        send_btn = QPushButton("Send")
        cancel_btn = QPushButton("Cancel")
        send_btn.clicked.connect(self.send_file)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(send_btn)
        btn_layout.addWidget(cancel_btn)
        
        layout.addWidget(QLabel(f"Select a file to send to {target_user}:"))
        layout.addLayout(file_layout)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        
        # Progress bar for sending
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path.setText(file_path)
            
    def send_file(self):
        file_path = self.file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file first!")
            return
            
        # Get file information
        file_name = file_path.split('/')[-1]
        file_size = os.path.getsize(file_path)
        
        # Send file transfer request
        self.parent.send_file_request(self.target_user, file_name, file_size, file_path)
        self.accept()




class AuthDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login / Register")
        self.setModal(True)
        self.resize(300, 150)

        layout = QVBoxLayout()
        self.choice = QComboBox()
        self.choice.addItems(["login", "register"])
        layout.addWidget(QLabel("Choose:"))
        layout.addWidget(self.choice)

        self.username = QLineEdit()
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password)

        self.btn = QPushButton("Continue")
        self.btn.clicked.connect(self.accept)
        layout.addWidget(self.btn)

        self.setLayout(layout)

    def get_data(self):
        return self.choice.currentText(), self.username.text(), self.password.text()


class PrivateChatWindow(QDialog):
    def __init__(self, parent, target_user):
        super().__init__(parent)
        self.target_user = target_user
        self.setWindowTitle(f"Private Chat - {target_user}")
        self.setGeometry(300, 300, 400, 300)

        layout = QVBoxLayout()
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit()
        send_btn = QPushButton("Send")
        file_btn = QPushButton("Send File")
        send_btn.clicked.connect(self.send_message)
        file_btn.clicked.connect(self.send_file_dialog)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(send_btn)
        input_layout.addWidget(file_btn)
        layout.addLayout(input_layout)
        self.setLayout(layout)

    def append_message(self, message):
        self.chat_display.append(message)

    def send_message(self):
        msg = self.msg_input.text().strip()
        if msg:
            full_msg = f"/msg {self.target_user} {msg}"
            self.parent().client_socket.send(full_msg.encode())
            self.append_message(f"[You → {self.target_user}]: {msg}")
            self.parent().log_private_message(self.target_user, f"[You → {self.target_user}]: {msg}")
            self.msg_input.clear()

    def send_file_dialog(self):
        dialog = FileTransferDialog(self.parent(), self.target_user)
        dialog.exec_()

class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chat + One-on-One Video Call")
        self.setGeometry(200, 200, 550, 500)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.HOST = '192.168.25.235'
        self.PORT = 5000
        self.nickname = ""
        self.private_chats = {}
        self.chat_logs = {}

        self.comm = Communicator()
        self.comm.message_received.connect(self.display_message)
        self.comm.video_call_request.connect(self.ask_user_video_call)
        self.connect_to_server()


    def init_ui(self):
        self.resize(700, 500)
        main_layout = QHBoxLayout()

        # === LEFT PANEL ===
        left_layout = QVBoxLayout()

        self.nick_label = QLabel(f"Nickname: {self.nickname}")
        left_layout.addWidget(self.nick_label)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        left_layout.addWidget(self.chat_display)

        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit()
        self.send_btn = QPushButton("Send")
        self.file_btn = QPushButton("Send File")
        self.send_btn.clicked.connect(self.send_message)
        self.file_btn.clicked.connect(self.send_file_to_room)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self.send_btn)
        input_layout.addWidget(self.file_btn)
        left_layout.addLayout(input_layout)

        self.leave_btn = QPushButton("Leave Chat")
        self.leave_btn.clicked.connect(self.leave_chat)
        left_layout.addWidget(self.leave_btn)

        # === RIGHT PANEL ===
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Online Users:"))
        self.user_list = QListWidget()
        right_layout.addWidget(self.user_list)

        main_layout.addLayout(left_layout, stretch=3)
        main_layout.addLayout(right_layout, stretch=1)
        self.setLayout(main_layout)

        # Setup double click connection
        self.user_list.itemDoubleClicked.connect(self.open_private_chat)

        # Timer to refresh users
        self.user_refresh_timer = QTimer()
        self.user_refresh_timer.timeout.connect(self.request_user_list)
        self.user_refresh_timer.start(10000)

    def handle_room_file_offer(self, sender, file_name, file_size):
        """Handle when someone offers a file to the room"""
        formatted_size = self.format_size(int(file_size))
        self.chat_display.append(f"📁 {sender} offered to share: {file_name} ({formatted_size})")
        
        # Instead of trying to insert a widget, let's add a clickable text link
        self.chat_display.append(f"[Click here to download {file_name} from {sender}]")
        
        # Store file offer information
        if not hasattr(self, 'room_file_offers'):
            self.room_file_offers = {}
        
        offer_key = f"{sender}:{file_name}"
        self.room_file_offers[offer_key] = {
            'sender': sender,
            'file_name': file_name,
            'file_size': int(file_size)
        }
        
        # Connect click event if not already connected
        if not hasattr(self, 'chat_click_connected'):
            self.chat_click_connected = True
            self.chat_display.mousePressEvent = self.chat_display_clicked

    def chat_display_clicked(self, event):
        """Handle clicks in the chat display to detect download links"""
        cursor = self.chat_display.cursorForPosition(event.pos())
        cursor.select(QTextCursor.LineUnderCursor)
        line = cursor.selectedText()
        
        # Check if this is a download link
        if line.startswith('[Click here to download ') and ']' in line:
            # Extract sender and filename
            parts = line.split(' from ')
            if len(parts) == 2:
                file_name = parts[0].replace('[Click here to download ', '')
                sender = parts[1].replace(']', '')
                
                # Request the file
                self.request_room_file(sender, file_name)
        
        # Call the original mousePressEvent if it exists
        original_handler = getattr(self, 'original_mouse_press', None)
        if original_handler:
            original_handler(event)

    def request_room_file(self, sender, file_name):
        """Request a file that was offered in the room"""
        # Ask where to save the file
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File", file_name)
        if not save_path:
            return
            
        # Send request to the sender
        self.client_socket.send(f"/get_room_file {sender} {file_name}".encode())
        
        # Prepare for receiving
        self.incoming_files = getattr(self, 'incoming_files', {})
        self.incoming_files[sender] = {
            'path': save_path,
            'size': 0,  # Will be updated when transfer begins
            'received': 0,
            'file': None
        }
        
        self.chat_display.append(f"📥 Requesting {file_name} from {sender}...")

    def handle_room_file_request(self, requestor, file_name):
        """Handle when someone requests our shared room file"""
        if not hasattr(self, 'room_file') or self.room_file['name'] != file_name:
            return
            
        self.chat_display.append(f"📤 {requestor} requested your shared file: {file_name}")
        
        # Start file transfer in a thread
        threading.Thread(
            target=self.send_file_data,
            args=(requestor, self.room_file['path']),
            daemon=True
        ).start()
    
    def send_file_to_room(self):
        """Open file dialog and send file to all users in the room"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share")
        if not file_path:
            return
            
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # Ask for confirmation due to multiple transfers
        reply = QMessageBox.question(
            self, 
            "Confirm File Share",
            f"Share {file_name} ({self.format_size(file_size)}) with everyone?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Store file info for transfers
            self.room_file = {
                'path': file_path,
                'name': file_name,
                'size': file_size
            }
            
            # Send announcement to room
            self.client_socket.send(f"/room_file {file_name} {file_size}".encode())
            self.chat_display.append(f"📤 You offered to share {file_name} with the room")


    def send_file_request(self, target_user, file_name, file_size, file_path):
        """Send file transfer request to target user"""
        request = f"/file_request {target_user} {file_name} {file_size}"
        self.client_socket.send(request.encode())
        
        # Store file path for later use when accepted
        self.pending_file_transfers = getattr(self, 'pending_file_transfers', {})
        self.pending_file_transfers[target_user] = {
            'path': file_path,
            'size': file_size,
            'name': file_name
        }
        
        # Show message in chat
        self.chat_display.append(f"File transfer request sent to {target_user} for {file_name}")

    def handle_file_request(self, sender, file_name, file_size):
        """Handle incoming file transfer request"""
        # Ask user if they want to accept the file
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setWindowTitle("File Transfer Request")
        msg_box.setText(f"{sender} wants to send you a file:\n{file_name} ({self.format_size(file_size)})")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        
        if msg_box.exec_() == QMessageBox.Yes:
            # Ask where to save the file
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save File", file_name
            )
            if save_path:
                # Accept the request
                self.client_socket.send(f"/file_accept {sender} {file_name}".encode())
                
                # Create a directory for incoming files if it doesn't exist
                self.incoming_files = getattr(self, 'incoming_files', {})
                self.incoming_files[sender] = {
                    'path': save_path,
                    'size': int(file_size),
                    'received': 0,
                    'file': None
                }
        else:
            # Reject the request
            self.client_socket.send(f"/file_reject {sender} {file_name}".encode())

    def format_size(self, size):
        """Format file size in human-readable format"""
        size = int(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def start_file_transfer(self, target_user):
        """Start sending file after request is accepted"""
        if not hasattr(self, 'pending_file_transfers') or target_user not in self.pending_file_transfers:
            return
            
        file_info = self.pending_file_transfers[target_user]
        file_path = file_info['path']
        
        # Start file transfer in a separate thread
        threading.Thread(
            target=self.send_file_data,
            args=(target_user, file_path),
            daemon=True
        ).start()

    def send_file_data(self, target_user, file_path):
        """Send file data in chunks"""
        try:
            self.chat_display.append(f"📤 Starting file transfer to {target_user}...")
            # Create a dedicated socket for file transfer
            file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_socket.connect((self.HOST, self.PORT + 1))  # Use PORT+1 for file transfers
            
            # Send target user to server
            file_socket.send(f"{self.nickname}\n{target_user}".encode())
            
            # Open file and send in chunks
            file_size = os.path.getsize(file_path)
            sent = 0
            
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    # Read a chunk
                    chunk = f.read(4096)
                    if not chunk:
                        break
                        
                    # Send the chunk
                    file_socket.sendall(chunk)
                    sent += len(chunk)
                    
                    # Update progress (emit signal to update UI)
                    progress = int((sent / file_size) * 100)
                    self.comm.message_received.emit(f"[File Transfer] Sending to {target_user}: {progress}%")
            
            file_socket.close()
            self.comm.message_received.emit(f"✅ File sent to {target_user} successfully.")
            
        except Exception as e:
            self.comm.message_received.emit(f"❌ Error sending file: {str(e)}")

    def receive_file_data(self, sender, file_socket):
        """Receive file data from socket"""
        if not hasattr(self, 'incoming_files') or sender not in self.incoming_files:
            file_socket.close()
            return
            
        file_info = self.incoming_files[sender]
        file_path = file_info['path']
        file_size = file_info['size']
        
        try:
            with open(file_path, 'wb') as f:
                received = 0
                while received < file_size:
                    chunk = file_socket.recv(4096)
                    if not chunk:
                        break
                        
                    f.write(chunk)
                    received += len(chunk)
                    
                    # Update progress
                    progress = int((received / file_size) * 100)
                    self.comm.message_received.emit(f"[File Transfer] Receiving from {sender}: {progress}%")
            
            self.comm.message_received.emit(f"✅ File received from {sender} successfully: {file_path}")
        except Exception as e:
            self.comm.message_received.emit(f"❌ Error receiving file: {str(e)}")
        finally:
            file_socket.close()

    def connect_to_server(self):
        try:
            dialog = AuthDialog()
            if dialog.exec_() != QDialog.Accepted:
                self.close()
                return

            choice, username, password = dialog.get_data()

            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password cannot be empty!")
                self.close()
                return

            from user_auth import register_user, authenticate_user

            if choice == "register":
                if not register_user(username, password):
                    QMessageBox.warning(self, "Error", "Username already exists!")
                    self.close()
                    return
                QMessageBox.information(self, "Success", "Registered successfully!")
            else:
                if not authenticate_user(username, password):
                    QMessageBox.warning(self, "Error", "Invalid credentials!")
                    self.close()
                    return

            self.nickname = username
            self.init_ui()
            self.client_socket.connect((self.HOST, self.PORT))
            self.client_socket.sendall((self.nickname + "\n").encode())
            # Start listening before sending nickname!
            threading.Thread(target=self.receive_messages, daemon=True).start()

            self.start_video_server_once()

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))
            self.close()

    def start_video_server_once(self):
        print("[📷] Starting video server...")

        if not hasattr(self, 'video_server_started'):
            self.video_server_started = True
            threading.Thread(target=start_video_server, daemon=True).start()

    def request_user_list(self):
        try:
            if self.client_socket:
                self.client_socket.send("/users".encode())
        except Exception as e:
            print(f"❌ Failed to request user list: {e}")


    def update_user_list(self, users):
        print(f"🧾 Raw user list received: {users}")
        cleaned_users = []
        for u in users:
            u = u.strip()
            if u and u != self.nickname:
                cleaned_users.append(u)
        print(f"👥 Updating user list: {cleaned_users}")
        self.user_list.blockSignals(True)
        self.user_list.clear()
        self.user_list.addItems(users)
        self.user_list.blockSignals(False)

        try:
            self.user_list.itemDoubleClicked.disconnect()
        except:
            pass
        self.user_list.itemDoubleClicked.connect(self.open_private_chat)

    def open_private_chat(self, item):
        username = item.text()
        print(f"🖱️ User clicked in sidebar: '{username}'")
        if username != self.nickname:
            self.show_dm_window(username)

    def ask_user_video_call(self, caller, caller_ip):
        print(f"🧠 Prompting user with call popup for {caller} at {caller_ip}...")
        reply = QMessageBox.question(
            self,
            "Incoming Video Call",
            f"📞 {caller} is calling you. Accept?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            print("✅ Call accepted. Starting video client...")
            self.start_video_server_once()
            threading.Thread(target=start_video_client, args=(caller_ip,), daemon=True).start()
            self.comm.message_received.emit(f"✅ Video call accepted from {caller}")
        else:
            print("❌ Call declined.")
            self.comm.message_received.emit(f"❌ Call from {caller} declined.")


    def show_dm_window(self, username, message=None, from_sender=True):
        def show():
            window = self.private_chats.get(username)
            if not window:
                window = PrivateChatWindow(self, username)
                self.private_chats[username] = window

                # Load chat history
                for msg in self.chat_logs.get(username, []):
                    window.append_message(msg)

            window.show()
            window.raise_()
            window.activateWindow()

            if message:
                prefix = f"[{username} → You]" if from_sender else f"[You → {username}]"
                log_line = f"{prefix}: {message}"
                window.append_message(log_line)
                self.log_private_message(username, log_line)

        QTimer.singleShot(0, show)

    def log_private_message(self, user, message):
        if user not in self.chat_logs:
            self.chat_logs[user] = []
        self.chat_logs[user].append(message)



    
    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                print("🛰️ Message from server:", repr(message))

                if message.startswith("/userlist"):
                    print("👥 User list received:", message)
                    users = message.split("\n")[1:]
                    self.update_user_list(users)
                    continue  # Prevent displaying it in the main chat box
                

                elif message.startswith("/room_file"):
                    # Someone is offering a file to the room
                    parts = message.split(maxsplit=3)
                    if len(parts) >= 3:
                        sender = parts[0].strip(':')
                        file_name = parts[1]
                        file_size = parts[2]
                        QTimer.singleShot(0, lambda: self.handle_room_file_offer(sender, file_name, file_size))

                elif message.startswith("/get_room_file_request"):
                    # Someone wants our shared file
                    _, requestor, file_name = message.split(maxsplit=2)
                    QTimer.singleShot(0, lambda: self.handle_room_file_request(requestor, file_name))

                elif message.startswith("[PM from"):
                    parts = message.split("]: ", 1)
                    if len(parts) == 2:
                        prefix, msg = parts
                        sender = prefix.split()[2]
                        self.show_dm_window(sender, msg, from_sender=True)
                
                elif message.startswith("[PM to"):
                    parts = message.split("]: ", 1)
                    if len(parts) == 2:
                        prefix, msg = parts
                        target = prefix.split()[2]
                        self.show_dm_window(target, msg, from_sender=False)

                elif message.startswith("/call_from"):
                    print("📞 Incoming call signal received:", repr(message))
                    parts = message.split()
                    print(f"🔍 Split message parts: {parts}")
                    if len(parts) >= 3:
                        caller = parts[1]
                        caller_ip = parts[2]
                        print(f"🛠️ Parsed caller: '{caller}', IP: '{caller_ip}'")
                        print("🔔 Scheduling ask_user_video_call...")
                        self.comm.video_call_request.emit(caller, caller_ip)
                        print("✅ Scheduled callback")
                    else:
                        print(f"❌ Not enough parts in call message: {parts}")

                elif message.startswith("/file_request"):
                    _, sender, file_name, file_size = message.split(maxsplit=3)
                    QTimer.singleShot(0, lambda: self.handle_file_request(sender, file_name, file_size))

                elif message.startswith("/file_accept"):
                    _, target, file_name = message.split(maxsplit=2)
                    self.comm.message_received.emit(f"✅ {target} accepted your file transfer request.")
                    QTimer.singleShot(0, lambda: self.start_file_transfer(target))

                elif message.startswith("/file_reject"):
                    _, target, file_name = message.split(maxsplit=2)
                    self.comm.message_received.emit(f"❌ {target} rejected your file transfer request.")

                elif message.startswith("/file_data"):
                    _, sender = message.split(maxsplit=1)
                    self.comm.message_received.emit(f"📩 Receiving file data from {sender}...")
                else:
                    self.comm.message_received.emit(message)

            except Exception as e:
                print("❌ Error receiving:", e)
                break

    def send_message(self):
        message = self.msg_input.text().strip()

        # ✅ If it's a call command, make sure the caller's video server is up
        if message.startswith("/call "):
            self.start_video_server_once()

        if message:
            self.client_socket.send(message.encode())
            self.msg_input.clear()


    def display_message(self, message):
        self.chat_display.append(f"{message}\n")

    def leave_chat(self):
        self.client_socket.send("/exit".encode())
        self.client_socket.close()
        self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())
