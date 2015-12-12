import socket
import sys
import time


def is_valid_ip(s):
    pieces = s.split('.')
    if len(pieces) != 4:
        return False
    try:
        return all(0 <= int(p) < 256 for p in pieces)
    except ValueError:
        return False


def start_latency_test(sock):
    while True:
        data, (ip, port) = sock.recvfrom(2048)
        data = str(data)[2:-1]
        if data == 'END_LATENCY_TRY':
            timestamp_1, (ip, port) = sock.recvfrom(2048)
            timestamp_1 = float(timestamp_1)
            timestamp_2 = time.time()
            sock.sendto(str(timestamp_2 - timestamp_1).encode('ascii'),
                        (ip, port))
            print(timestamp_2-timestamp_1)
        elif data == 'END_LATENCY_TEST':
            break


def get_socket():
    try:
        return socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

LOCAL_PORT = 7
DEFAULT_DEST_PORT = 5050

if __name__ == '__main__':

    if len(sys.argv) not in (2, 3):
        print('usage: python3 %s <SOURCE_IP> [<DEST_PORT>]' % sys.argv[0])
        sys.exit()

    src_ip = sys.argv[1]
    if not is_valid_ip(src_ip):
        print('src_ip: %s is not a valid ip address' % src_ip)
        sys.exit()

    if len(sys.argv) == 3:
        dest_port = int(sys.argv[2])
    else:
        dest_port = DEFAULT_DEST_PORT

    sock = get_socket()
    sock.bind((src_ip, LOCAL_PORT))

    packet_counter = 0
    while True:
        data, (ip, port) = sock.recvfrom(2048)
        data = str(data)[2:-1]
        if data == 'END_THROUGHPUT_TRY':
            x = sock.sendto(str(packet_counter).encode('ascii'), (ip, port))
            print('message sent: {}'.format(x))
            packet_counter = 0
        elif data == 'BEGIN_LATENCY_TEST':
            start_latency_test(sock)
        else:
            packet_counter += 1
