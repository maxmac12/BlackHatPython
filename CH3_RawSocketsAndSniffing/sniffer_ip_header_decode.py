import socket
import os
import struct
from ctypes import *

""" 
This script sniffs network packets received to a given host and decodes the 
packets to show packet type, source, and destination in human readable form.

Note: Promiscuous mode is needed which requires administrative privileges
    on Windows or root on Linux.
"""

# Host to listen on
if os.name == "nt":
    HOST = "192.168.1.114"
else:
    HOST = "192.168.1.115"


class IP(Structure):
    _fields_ = [
        ("ihl",          c_uint8, 4),
        ("version",      c_uint8, 4),
        ("tos",          c_uint8),
        ("len",          c_uint16),
        ("id",           c_uint16),
        ("offset",       c_uint16),
        ("ttl",          c_uint8),
        ("protocol_num", c_uint8),
        ("sum",          c_uint16),
        ("src",          c_uint32),
        ("dst",          c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # Map protocol constants to their names
        # TODO: Map remaining IP protocol numbers.
        self.protocol_map = {
            1:  "ICMP",
            2:  "IGMP",
            6:  "TCP",
            17: "UDP"
        }

        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


def main():
    # Create a raw socket and bind it to the public interface
    # Windows allows us to sniff all incoming packets regardless of protocol.
    # Linux forces us to specify that we are sniffing ICMP.
    if os.name == "nt":
        # Windows
        socket_protocol = socket.IPPROTO_IP
    else:
        # Linux
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    # Set the socket options to include IP headers in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # If we are using Windows, we need to send an IOCTL to turn on promiscuous mode.
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Read in a packet
            # TODO: Linux not sniffing packets.
            raw_buffer = sniffer.recvfrom(65565)[0]

            # Create an IP header from the first 20 bytes of the buffer
            ip_header = IP(raw_buffer[0:20])

            # Print out the protocol that was detected and the hosts
            print("Protocol: {} {} -> {}".format(ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    # Handle CTRL-C
    except KeyboardInterrupt:
        # If we are using Windows, turn off promiscuous mode.
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
    main()
