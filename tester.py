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


def checksum(msg):
    s = 0

    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            w = msg[i] + (msg[i + 1] << 8)
        else:
            w = msg[i]
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)

    s = ~s & 0xffff

    return s


def build_packet(src_ip, dst_ip):

    # pacote deve ter esse formato de acordo com a rfc2544
    """
    UDP echo request on Ethernet

           -- DATAGRAM HEADER
           offset data (hex)            description
           00     xx xx xx xx xx xx     set to dest MAC address
           06     xx xx xx xx xx xx     set to source MAC address
           12     08 00                 type

           -- IP HEADER
           14     45                    IP version - 4 header length 5 4
          byte units
           15     00                    TOS
           16     00 2E                 total length*
           18     00 00                 ID
           20     00 00                 flags (3 bits) - 0 fragment
          offset-0
           22     0A                    TTL
           23     11                    protocol - 17 (UDP)
           24     C4 8D                 header checksum*
           26     xx xx xx xx           set to source IP address**
           30     xx xx xx xx           set to destination IP address**

           -- UDP HEADER
           34     C0 20                 source port
           36     00 07                 destination port 07 = Echo
           38     00 1A                 UDP message length*
           40     00 00                 UDP checksum

           -- UDP DATA
           42     00 01 02 03 04 05 06 07    some data***
           50     08 09 0A 0B 0C 0D 0E 0F

          * - change for different length frames

          ** - change for different logical streams

          *** - fill remainder of frame with incrementing octets,
          repeated if required by frame length

    Values to be used in Total Length and UDP message length fields
    """

    # ip header
    ip_version = 0x45         # 1 byte, version + ihl
    ip_tos = 0x00             # 1 byte, dscp+ecn
    ip_total_length = 0x0000  # 2 bytes, kernel will calculate
    ip_id = 0x0000            # 2 bytes
    ip_frag_offset = 0x0000   # 2 bytes, flags + fragment offset
    ip_ttl = 0x0a             # 1 byte
    ip_protocol = socket.IPPROTO_UDP  # 1 byte
    ip_checksum = 0x0000      # 2 bytes, kernel will calculate
    # 4 bytes, converte string pra bytes
    ip_src_addr = socket.inet_aton(src_ip)
    # 4 bytes, converte string pra bytes
    ip_dest_addr = socket.inet_aton(dst_ip)

    """
    ! = network order (big-endian)
    B = unsigned byte -> [0, 255]
    H = unsigned word -> [0,65535]
    4s = char[4] -> [0, 255]x4
    """
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_version, ip_tos,
                            ip_total_length, ip_id, ip_frag_offset, ip_ttl,
                            ip_protocol, ip_checksum, ip_src_addr,
                            ip_dest_addr)

    # udp header
    udp_src_port = 0xc020   # 2 bytes
    udp_dest_port = 0x0007  # 2 bytes
    udp_msg_length = 0      # 2 bytes
    udp_checksum = 0        # 2 bytes

    # ! network order (big-endian)
    # H = unsigned word -> [0,65535]
    udp_header = struct.pack("!HHHH", udp_src_port, udp_dest_port,
                             udp_msg_length, udp_checksum)

    udp_data = "hello".encode('ascii')

    src_addr = socket.inet_aton(src_ip)
    dest_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_UDP
    udp_length = len(udp_header) + len(udp_data)

    # header pra calcular o checksum do udp
    pseudo_header = struct.pack('!4s4sBBH', src_addr, dest_addr, placeholder,
                                protocol, udp_length)
    pseudo_header += udp_header + udp_data

    udp_checksum = checksum(pseudo_header)
    udp_header = struct.pack('!HHHH', udp_src_port, udp_dest_port, udp_length,
                             udp_checksum)

    # monta o pacote de acordo com o rfc2544

    packet = ip_header + udp_header + udp_data
    print_binary(packet)
    return packet


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
        return socket.socket(socket.AF_INET,
                             socket.SOCK_RAW,
                             socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

PACKET_SIZES = [64, 128, 256, 512, 1024, 1280, 1518]


def socket_send(src_ip, dst_ip, num_pkt_sent, num_pkt_recv):
    MAX_TIME = 2

    sock = get_socket()
    packet = build_packet(src_ip, dst_ip)
    packet_rate = 1 # packets per second
    highest_lossless_rate = -1
    highest_loss_rate = -1

    while True:
        period = 1/packet_rate
        time_counter = 0.0
        with num_pkt_sent.get_lock():
            num_pkt_sent.value = 0

        """
        o loop executa aproximadamente pelo tempo (em segundos) definido
        em MAXX_TIME
        """
        while time_counter < MAX_TIME:
            print("Sending packet1 to: %s" % dst_ip)
            sock.sendto(packet, (dst_ip, 0))
            with num_pkt_sent.get_lock():
                num_pkt_sent.value += 1
            time.sleep(period)
            time_counter += period

        """
        Para de enviar mensagens e espera um momento (sleep) para a outra
        thread terminar de receber os pacotes
        """
        print("Terminating send process")
        time.sleep(1)

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
            if 0 < highest_loss_rate <= packet*2:
                packet_rate = (highest_loss_rate + packet_rate) / 2
            else:
                packet_rate *= 2
            print('num_pkt_sent ({}) <= num_pkt_recv ({})'.format(
                  num_pkt_sent.value, num_pkt_recv.value))
            print('Increasing rate to {} pps'.format(packet_rate))


def socket_recv(src_ip, dst_ip, packet_sz, num_pkt_recv):
    sock = get_socket()

    while True:
        sz, addr = sock.recvfrom(packet_sz)
        print('Packet received from %s' % addr)
        num_pkt_recv.value += 1

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
        print('{} is not a valid packet size. Packet must have on of the '
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
                                     args=(src_ip, dst_ip, num_pkt_sent,
                                           num_pkt_recv))
    recv_p = multiprocessing.Process(target=socket_recv,
                                     args=(src_ip, dst_ip, packet_sz,
                                           num_pkt_recv))

    recv_p.start()
    send_p.start()
    print("joining send_p")
    send_p.join()
    print("joining recv_p")
    recv_p.join()
    print("Ending program")
    #sock.sendto(packet, (dst_ip, 0))
