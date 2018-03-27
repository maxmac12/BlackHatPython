import sys
import socket
from threading import Thread


def hexdump(src, length=16):
    result = []

    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join("{:02X}".format(x) for x in s)
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])  # Only decode ASCII characters.
        result.append("{:04X}  {}  {}".format(i, hexa, text))

    print('\n'.join(result))


def receive_from(connection):
    buffer = b""

    # We set a 2 second timeout; depending on your target, this may need to be adjusted
    connection.settimeout(2)

    try:
        # Keep reading into the buffer until there is no more data or we timeout
        while True:
            data = connection.recv(4096)

            if not data:
                break

            buffer += data
    except socket.timeout:
        print("[!!] Receive Timeout!")
    except Exception as inst:
        print("[!!] {} {}".format(type(inst), inst))
    except:
        print("Unknown Receive Exception!")

    return buffer


# Modify any requests destined for the remote host
def request_handler(buffer):
    # Perform packet modifications
    return buffer


# Modify any responses destined for the local host
def response_handler(buffer):
    # Perform packet modification
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # Connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    print("[*] Connected to remote host %s:%d" % (remote_host, remote_port))

    # Receive data from the remote if necessary
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # Send it to our response handler
        remote_buffer = response_handler(remote_buffer)

        # If we have data to send to our local client, send it
        if len(remote_buffer):
            print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
            client_socket.send(remote_buffer)

    # Now lets loop and read from local, send to remote, send to local, and repeat
    while True:
        # Read from local host
        local_buffer = receive_from(client_socket)

        if len(local_buffer):
            print("[==>] Received %d bytes from localhost." % len(local_buffer))
            hexdump(local_buffer)

            # Send it to our request handler
            local_buffer = request_handler(local_buffer)

            # Send the data to the remote host
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        # Receive back a response
        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            # Send received data to the response handler
            remote_buffer = response_handler(remote_buffer)

            # Send response to the local socket
            client_socket.send(remote_buffer)

            print("[<==] Sent to localhost.")

        # If no more data on either side, close the connections
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, local_port))
    except:
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s:%d" % (local_host,local_port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # Print out the local connection information
        print("[==>] Received incoming connection from %s:%d" % (addr[0], addr[1]))

        # Start a thread to talk to the remote host
        proxy_thread = Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()
        #proxy_thread.run()


def main():
    # Check if enough arguments have been given.
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    # Setup local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # Setup remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # This tells our proxy to connect and receive data before sending to the remote host
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    # Spin up the listening socket
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == '__main__':
    main()