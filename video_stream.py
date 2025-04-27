import cv2
import socket
import pickle
import struct

VIDEO_PORT = 10006

def start_video_server(host='0.0.0.0', port=VIDEO_PORT):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    conn, _ = server.accept()
    data = b""
    payload_size = struct.calcsize("Q")

    try:
        while True:
            while len(data) < payload_size:
                packet = conn.recv(4 * 1024)
                if not packet:
                    return
                data += packet
            packed_msg_size = data[:payload_size]
            data = data[payload_size:]
            msg_size = struct.unpack("Q", packed_msg_size)[0]
            while len(data) < msg_size:
                data += conn.recv(4 * 1024)
            frame_data = data[:msg_size]
            data = data[msg_size:]
            frame = pickle.loads(frame_data)
            cv2.imshow("🔴 Incoming Video", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
    except:
        pass
    cv2.destroyAllWindows()
    conn.close()

def start_video_client(host, port=VIDEO_PORT):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    cam = cv2.VideoCapture(0)

    try:
        while cam.isOpened():
            ret, frame = cam.read()
            if not ret:
                break
            data = pickle.dumps(frame)
            msg = struct.pack("Q", len(data)) + data
            client.sendall(msg)
    except:
        pass
    cam.release()
    client.close()
