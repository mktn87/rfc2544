#!/usr/bin/env python3

import sys
import socket
import struct
import time
import multiprocessing

PORT = 5050

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

def get_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('1.0.0.0', 0))
        IP = s.getsockname()[1]
    except:
        IP = 0
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


def socket_send(src_ip, dst_ip, length):
    MAX_FRAME_RATE = MAX_FRAME_RATES[PACKET_SIZES.index(length)]
    #MAX_PACKETS = MAX_FRAME_RATE*20


    sock = get_socket()
    sock.bind((src_ip, PORT))
    packet = '!'.encode('ascii')
    packet += ("*" * (length - 44)).encode('ascii')
    packet += '!'.encode('ascii')
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 10);
    packet_rate = MAX_FRAME_RATE  # packets per second
    highest_lossless_rate = -1
    highest_loss_rate = 0

    while True:
        period = 1 / packet_rate
        print(period)
        num_pkt_sent = 0
        MAX_PACKETS = packet_rate*20

        """
        o loop executa aproximadamente pelo tempo (em segundos) definido
        em MAXX_TIME
        """
        while num_pkt_sent < MAX_PACKETS:
            #print("Sending packet to: {}".format(dst_ip))
            #print(packet)
            sock.sendto(packet, (dst_ip, 7))
            num_pkt_sent += 1
            time.sleep(period)

        """
        Para de enviar mensagens e espera um momento (sleep) para a outra
        thread terminar de receber os pacotes
        """
        print("\n{} pacotes enviados.".format(num_pkt_sent))
        time.sleep(1)
        """
        Envia três mensagens END para o servidor saber que deve parar de
        receber os dados.
        """
        end_message = "END".encode('ascii')
        sock.sendto(end_message, (dst_ip, 7))
        print("blocking")
        num_pkt_recv, addr = sock.recvfrom(1024)
        num_pkt_recv = int(num_pkt_recv)
        print("Received {} from {}".format(num_pkt_recv, addr))
        print("received")

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
        print()
        print('highest_loss_rate: {}, highest_lossless_rate: {}'.format(
            highest_loss_rate, highest_lossless_rate))
        print(num_pkt_recv, num_pkt_recv)
        if num_pkt_sent > num_pkt_recv:
            #if packet_rate > highest_loss_rate:
            highest_loss_rate = packet_rate
            packet_rate //= 2
            if packet_rate <= 1:
                break

            # if highest_lossless_rate < 0:
            #     print("Throughput < 1 pps")
            #     break
            #packet_rate = (highest_lossless_rate + packet_rate) // 2
            print('num_pkt_sent ({}) > num_pkt_recv ({})'.format(
                  num_pkt_sent, num_pkt_recv))
            print('Reducing rate to {} pps'.format(packet_rate))
        else:
            s = abs(packet_rate - highest_loss_rate) // 2
            packet_rate += s
            #packet_rate = (packet_rate * 3) // 2

            print('num_pkt_sent ({}) <= num_pkt_recv ({})'.format(
                  num_pkt_sent, num_pkt_recv))
            print('Increasing rate to {} pps'.format(packet_rate))

            if packet_rate < 2 or s == 0:
            #if packet_rate < 2 or packet_rate == highest_loss_rate:
                print('\npacket_rate == {}'.format(packet_rate))
                print('s == {}'.format(s))
                break
            # if packet_rate == highest_lossless_rate:
            #     print("Highest rate found: {} pps".format(packet_rate))
            #     break
            # highest_lossless_rate = packet_rate
            # if 0 < highest_loss_rate <= packet_rate * 2:
            #    packet_rate = (highest_loss_rate + packet_rate) // 2
            # else:
            #     packet_rate *= 2

    print("Highest rate found: {} pps".format(packet_rate))

PACKET_SIZES = [64, 128, 256, 512, 1024, 1280, 1280, 1518]
MAX_FRAME_RATES = [14880, 8445, 4528, 2349, 1586, 1197, 961, 812]
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

    socket_send(src_ip, dst_ip, packet_sz)
