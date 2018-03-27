import socket
import os

""" 
This script sniffs network packets received to a given host.

Note: Promiscuous mode is needed which requires administrative privileges
    on Windows or root on Linux.
"""
# Host to listen on
if os.name == "nt":
    HOST = "192.168.1.114"
else:
    HOST = "192.168.1.115"

# Create a raw socket and bind it to the public interface
# Windows allows us to sniff all incoming packets regardless of protocol.
# Linux forces us to specify that we are sniffing ICMP.
if os.name == "nt":
    # Windows
    socket_protocol = socket.IPPROTO_IP
else:
    # Linux
    socket_protocol = socket.IPPROTO_TCP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((HOST, 0))

# Set the socket options to include IP headers in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# If we are using Windows, we need to send an IOCTL to turn on promiscuous mode.
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Read in a single packet.
print(sniffer.recvfrom(65565))

# If we are using Windows, turn off promiscuous mode.
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)