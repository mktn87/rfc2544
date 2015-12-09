#!/usr/bin/env python3

import sys
import socket
import struct
import time
import multiprocessing


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


def get_socket():
    try:
        return socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()


def socket_send(src_ip, dst_ip, length, num_pkt_sent, num_pkt_recv):
    MAX_TIME = 60

    sock = get_socket()
    packet = '!'.encode('ascii')
    packet += ("*" * (length - 44)).encode('ascii')
    packet += '!'.encode('ascii')
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 10);
    packet_rate = 1  # packets per second
    highest_lossless_rate = -1
    highest_loss_rate = -1

    while True:
        period = 1 / packet_rate
        time_counter = 0.0
        with num_pkt_sent.get_lock():
            num_pkt_sent.value = 0

        """
        o loop executa aproximadamente pelo tempo (em segundos) definido
        em MAXX_TIME
        """
        while time_counter < MAX_TIME:
            print("Sending packet to: {}".format(dst_ip))
            print(packet)
            # endereço e porta ja informado no pacote
            sock.sendto(packet, (dst_ip, 7))
            with num_pkt_sent.get_lock():
                num_pkt_sent.value += 1
            time.sleep(period)
            time_counter += period

        """
        Para de enviar mensagens e espera um momento (sleep) para a outra
        thread terminar de receber os pacotes
        """
        print("Terminating send process")
        time.sleep(10)

        """
        Se o numero de pacotes enviados for iguais aos recebidos reduz a taxa
        para:
                TAXA ATUAL
            +   MAIOR TAXA ENCONTRADA SEM PERDAS ATEH AGORA
            /   2
            (ou seja, média entre as duas taxas)

        Caso contrario, a taxa é aumentada para:

                TAXA ATUAL
            *   2

        A menos que a MAIOR TAXA ENCONTRADA COM PERDAS ATEH AGORA seja menor
        que 2x TAXA ATUAL. Nesse caso a nova taxa se torna:

                TAXA ATUAL
            +   MAIOR TAXA ENCONTRADA COM PERDAS ATEH AGORA
            /   2
            (ou seja, média entre as duas taxas)

        Se a TAXA ATUAL == MAIOR TAXA ENCONTRADA SEM PERDAS, então a taxa atual
        servirá para o calculo de throughput e o processo é terminado.

        Se a MAIOR TAXA ENCONTRADA SEM PERDAS < 0, no momento de fazer a
        redução da taxa, então o processo nunca irá encontrar uma taxa melhor
        do que esta e o programa acaba.

        """
        if num_pkt_sent.value > num_pkt_recv.value:
            if packet_rate > highest_loss_rate:
                highest_loss_rate = packet_rate
            if highest_lossless_rate < 0:
                print("Throughput < 1 pps")
                break
            packet_rate = (highest_lossless_rate + packet_rate) / 2
            print('num_pkt_sent ({}) > num_pkt_recv ({})'.format(
                  num_pkt_sent.value, num_pkt_recv.value))
            print('Reducing rate to {} pps'.format(packet_rate))
        else:
            if packet_rate == highest_lossless_rate:
                print("Highest rate found: {} pps".format(packet_rate))
                break
            highest_lossless_rate = packet_rate
            if 0 < highest_loss_rate <= packet * 2:
                packet_rate = (highest_loss_rate + packet_rate) / 2
            else:
                packet_rate *= 2
            print('num_pkt_sent ({}) <= num_pkt_recv ({})'.format(
                  num_pkt_sent.value, num_pkt_recv.value))
            print('Increasing rate to {} pps'.format(packet_rate))


def socket_recv(src_ip, dst_ip, packet_sz, num_pkt_recv):
    sock = get_socket()
    sock.bind((src_ip, 7))

    while True:
        sz, addr = sock.recvfrom(packet_sz)
        print('Packet received from %s' % addr)
        num_pkt_recv.value += 1

PACKET_SIZES = [64, 128, 256, 512, 1024, 1280, 1518]
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print('usage: python3 %s <DESTINATION_IP> <PACKET_SIZE>' % sys.argv[0])
        sys.exit()

    dst_ip = sys.argv[1]
    if not is_valid_ip(dst_ip):
        print('dst_ip: %s is not a valid ip address' % dst_ip)
        sys.exit()

    packet_sz = int(sys.argv[2])
    if packet_sz not in PACKET_SIZES:
        print('{} is not a valid packet size.\nPacket must have on of the '
              'follow sizes: {}.'.format(packet_sz, PACKET_SIZES))
        sys.exit()

    src_ip = get_local_ip()

    print('src ip is %s' % src_ip)
    print('dst ip is %s' % dst_ip)
    print('packet size is %d' % packet_sz)

    # Shared memory variables
    num_pkt_sent = multiprocessing.Value('d', 0)
    num_pkt_recv = multiprocessing.Value('d', 0)

    send_p = multiprocessing.Process(target=socket_send,
                                     args=(src_ip, dst_ip, packet_sz,
                                           num_pkt_sent, num_pkt_recv))
    recv_p = multiprocessing.Process(target=socket_recv,
                                     args=(src_ip, dst_ip, packet_sz,
                                           num_pkt_recv))

    recv_p.start()
    send_p.start()
    send_p.join()
    recv_p.join()
