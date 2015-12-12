#!/usr/bin/env python3

import sys
import socket
import time

DEFAULT_SRC_PORT = 5050
N = 4


def print_binary(header):
    i = 0
    for c in header:
        if i == 4:
            print()
            i = 0
        b = format(c, '#010b')[2:] + " "
        b = b[0:4] + " " + b[4:]

        print(b, end="")
        i += 1
    print()


def is_valid_ip(s):
    pieces = s.split('.')
    if len(pieces) != 4:
        return False
    try:
        return all(0 <= int(p) < 256 for p in pieces)
    except ValueError:
        return False


def get_socket():
    try:
        return socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()


def socket_send(src_ip, dst_ip, src_port, length):
    MAX_FRAME_RATE = MAX_FRAME_RATES[PACKET_SIZES.index(length)]

    sock = get_socket()
    sock.bind((src_ip, src_port))
    sock.connect((dst_ip, 7))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 10)

    packet = ('!' + "*" * (length - 44) + '!').encode('ascii')

    packet_rate = MAX_FRAME_RATE  # packets per second

    highest_lossless_rate = 0
    lowest_loss_rate = 0

    no_drops_detected = True

    MAX_TIME = 2

    while True:
        period = N / packet_rate
        num_pkt_sent = 0
        MAX_PACKETS = packet_rate * MAX_TIME

        print("rate is {}".format(packet_rate))
        print('period is {}'.format(period))

        f.write('Rate = {}\n'.format(packet_rate))

        start = time.time()

        while num_pkt_sent < MAX_PACKETS:
            for _ in range(N):
                sock.sendall(packet)
                num_pkt_sent += 1
            time.sleep(period)

        end = time.time()
        total_time = end - start
        print("time = {}".format(total_time))

        """
        Para de enviar mensagens e espera um momento (sleep) para a outra
        thread terminar de receber os pacotes
        """
        print("\n{} pacotes enviados.".format(num_pkt_sent))
        time.sleep(5)
        """
        Envia três mensagens END para o servidor saber que deve parar de
        receber os dados.
        """
        end_message = "END_THROUGHPUT_TRY".encode('ascii')
        sock.send(end_message)
        print("Waiting for response...")
        num_pkt_recv, addr = sock.recvfrom(1024)
        num_pkt_recv = int(num_pkt_recv)
        print("Received {} from {}".format(num_pkt_recv, addr))

        # Se houve perdas, ou tempo superou tempo máximo em 15%
        if num_pkt_sent > num_pkt_recv or \
                abs(total_time - MAX_TIME) / MAX_TIME > 0.15:

            # Define o novo patamar mais baixo para a taxa que gerou perdas
            if packet_rate < lowest_loss_rate or no_drops_detected:
                lowest_loss_rate = packet_rate
                no_drops_detected = False

            # Reduz a taxa para o valor médio entre a taxa atual e a maior taxa
            # que não gerou perdas
            packet_rate = (highest_lossless_rate + packet_rate) // 2
            print('\tnum_pkt_sent ({}) > num_pkt_recv ({})'.format(
                  num_pkt_sent, num_pkt_recv))
            print('\tReducing rate to {} pps'.format(packet_rate))
            f.write('\tSent: {}, Received: {}\n'.format(
                num_pkt_sent, num_pkt_recv))
            f.write('\tReducing rate to {} pps\n'.format(packet_rate))

        # Se não houve perdas
        elif num_pkt_sent <= num_pkt_recv:
            # Significa que o programa encontrou esta taxa pela segunda vez.
            # Então o programa termina.
            if packet_rate == highest_lossless_rate:
                break

            # Define o novo patamar inferion para taxa sem perda
            if packet_rate > highest_lossless_rate:
                highest_lossless_rate = packet_rate

            if no_drops_detected:
                packet_rate *= 2
            else:
                packet_rate = (lowest_loss_rate + packet_rate) // 2

            print('\tnum_pkt_sent ({}) <= num_pkt_recv ({})'.format(
                  num_pkt_sent, num_pkt_recv))
            print('\tIncreasing rate to {} pps'.format(packet_rate))
            f.write('\tSent: {}, Received: {}\n'.format(
                num_pkt_sent, num_pkt_recv))
            f.write('\tIncreasing rate to {} pps\n'.format(packet_rate))

        print('\tlowest_loss_rate: {}, highest_lossless_rate: {}'.format(
            lowest_loss_rate, highest_lossless_rate))
        print('\ttotal MB = {}'.format(
            num_pkt_sent * total_time * length // 1024 // 1024))
        print()
        f.write('\tlowest_loss_rate: {}, highest_lossless_rate: {}\n'.format(
            lowest_loss_rate, highest_lossless_rate))
        f.write('\ttotal MB = {}\n'.format(
            num_pkt_sent * total_time * length // 1024 // 1024))
        f.write('\n')

    print("Highest rate found: {} pps".format(packet_rate))
    f.write("Throughput: {} pps\n".format(packet_rate))
    f.write('\n')
    start_latency_test(sock, packet_rate, length)


def start_latency_test(sock, throughput, length):
    MAX_PACKETS = throughput * 60
    num_pkt_sent = 0
    f.write('\n\nStarting Latency Test\n\n')
    sock.send('BEGIN_LATENCY_TEST'.encode('ascii'))
    total = 0
    packet = ('!' + "*" * (length - 44) + '!').encode('ascii')
    period = N / throughput
    for i in range(20):
        print('Starting iteration {}'.format(i))
        for _ in range(2):
            while num_pkt_sent < MAX_PACKETS:
                for _ in range(N):
                    sock.sendall(packet)
                    num_pkt_sent += 1
                time.sleep(period)
            sock.send('END_LATENCY_TRY'.encode('ascii'))
            timestamp = time.time()
            sock.send(str(timestamp).encode('ascii'))
            latency, addr = sock.recvfrom(1024)
            latency = float(latency)
            print('Latency_{} = {}'.format(i, latency))
            total += latency
        total /= 2
        print('Mean latency_{} = {}'.format(i, latency))
        f.write('Mean latency_{} = {}\n'.format(i, latency))
    sock.send('END_LATENCY_TEST'.encode('ascii'))
    print('Final latency = {}'.format(total / 20))
    f.write('Final latency = {}\n'.format(total / 20))


PACKET_SIZES = [64,    128,  256,  512,  1024, 1280, 1280, 1518]
MAX_FRAME_RATES = [14880, 8445, 4528, 2349, 1586, 1197, 961,  812]
if __name__ == "__main__":

    if len(sys.argv) not in (4, 5):
        print('usage: python3 %s <SOURCE_IP> <DESTINATION_IP> <PACKET_SIZE>'
              '[<PORT>]' % sys.argv[0])
        sys.exit()

    src_ip = sys.argv[1]
    if not is_valid_ip(src_ip):
        print('src_ip: %s is not a valid ip address' % src_ip)
        sys.exit()

    dst_ip = sys.argv[2]
    if not is_valid_ip(dst_ip):
        print('dst_ip: %s is not a valid ip address' % dst_ip)
        sys.exit()

    packet_sz = int(sys.argv[3])
    if packet_sz not in PACKET_SIZES:
        print('{} is not a valid packet size.\nPacket must have on of the '
              'follow sizes: {}.'.format(packet_sz, PACKET_SIZES))
        sys.exit()

    if len(sys.argv) == 5:
        src_port = int(sys.argv[4])
    else:
        src_port = DEFAULT_SRC_PORT

    print('src ip is %s' % src_ip)
    print('dst ip is %s' % dst_ip)
    print('src_port is %d' % src_port)
    print('packet size is %d' % packet_sz)

    f = open('out.txt', 'w+')

    socket_send(src_ip, dst_ip, src_port, packet_sz)

    f.close()
