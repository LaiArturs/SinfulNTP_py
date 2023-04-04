#!/usr/bin/env python
from __future__ import print_function

import argparse
import socket
import time

from ntp_packet import (
    NTPPacket,
    NTPTimestamp,
)

def get_time(diff):
    return int(time.time() + diff)

def fake_server(args):

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind( (args.listen, args.port) )

    drift_start = get_time(args.diff)
    speed = 1 + args.error

    while True:
        packet, source = s.recvfrom(100)
        print('Received {length} byte packet from {source}'.format(length=len(packet), source=source[0]))
        packet = NTPPacket.from_bytes(packet)

        if packet.version not in (3, 4):
            print('Unsupported NTP version.')
            continue

        if packet.mode != 3:
            print('Not a client request.')
            continue

        try:
            print('Client time:', packet.transmit_timestamp)
        except:
            pass
        time_since_start = get_time(args.diff) - drift_start
        return_time = drift_start + time_since_start * speed
        return_time = int(return_time)

        response = NTPPacket()
        response.version = packet.version
        response.mode = 4
        response.stratum = 1
        response.reference_identifier = b'XFAK'
        response.origin_timestamp = packet.transmit_timestamp
        response.reference_timestamp = NTPTimestamp.from_unix_timestamp(return_time)
        response.receive_timestamp = NTPTimestamp.from_unix_timestamp(return_time)
        response.transmit_timestamp = NTPTimestamp.from_unix_timestamp(return_time)

        response = response.to_bytes()
        s.sendto(response, source)

def parse_bind_addr(address):
    address = socket.getaddrinfo(address, 123, 0, 0, 0, socket.AI_NUMERICHOST)
    address = address[0]
    if address[0] == socket.AF_INET:
        return '::ffff:' + address[4][0]
    else:
        return address[4][0]

def parse_args():
    parser = argparse.ArgumentParser(description='Fake NTP server')
    parser.add_argument('--listen', type=parse_bind_addr, default='::')
    parser.add_argument('--port', type=int, default=123, help="UDP port to run NTP server on, default will require root privileges.")
    parser.add_argument('--diff', type=int, default=0, help="Have NTP time differ from system time by this amount of seconds.")
    parser.add_argument('--error', type=float, default=0, help="Error of this NTP server that makes NTP client think that time runs faster or slower that it actually does. Use positive values for faster and negative values for slower. For example, 0.01, will make each second 1%% faster.")
    return parser.parse_args()

def main():
    args = parse_args()
    fake_server(args)

if __name__ == '__main__':
    main()
