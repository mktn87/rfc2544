import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('1.0.0.0', 0))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

LOCAL_PORT = 7
LOCAL_IP = get_local_ip()
DEST_PORT = 5050

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))

packet_counter = 0
while True:
    data, (ip, port) = sock.recvfrom(2048)
    if data != 'END':
        packet_counter += 1
    else:
        sock.sendto(str(packet_counter), (ip, DEST_PORT))
        packet_counter = 0


