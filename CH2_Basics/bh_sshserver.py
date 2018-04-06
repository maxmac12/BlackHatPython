import socket
import paramiko
import threading
import sys

# Global Values
USER          = ""
USER_PASSWORD = ""
KEY_FILE      = "./paramiko_demos/test_rsa.key"

# Using the key from the Paramiko demo files
host_key = paramiko.RSAKey(filename=KEY_FILE)

class Server (paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        else:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == USER) and (password == USER_PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED


def main():
    server = sys.argv[1]
    ssh_port = int(sys.argv[2])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, ssh_port))
        sock.listen(100)
        print("[+} Listening for connection...")
        client, addr = sock.accept()
    except Exception as e:
        sys.exit("[-] Listen failed: {}! Exiting.".format(str(e)))
    except:
        sys.exit("[-] Unknown Exception! Exiting.")

    print("[+] Connection Successful.")

    try:
        bhSession = paramiko.Transport(client)
        bhSession.add_server_key(host_key)
        server = Server()

        try:
            bhSession.start_server(server=server)
        except paramiko.SSHException as x:
            print("[-] SSH negotiation failed.")

        chan = bhSession.accept(20)
        print("[+] User Authenticated.")
        print(chan.recv(1024).decode('utf-8'))
        chan.send("Welcome to bh_ssh".encode('utf-8'))

        while True:
            try:
                # Get the command to be ran from the user.
                command = input("Enter Command: ")

                # Verify that a command was entered, otherwise sending will block.
                if len(command):
                    if command != "exit":
                        chan.send(command.encode('utf-8'))
                        print(chan.recv(1024).decode('utf-8') + "\n")
                    else:
                        chan.send("exit".encode('utf-8'))
                        print("Exiting.")
                        bhSession.close()
                        raise Exception("Exit")
            except KeyboardInterrupt:
                bhSession.close()

    except Exception as e:
        print("[-] Caught Exception: " + str(e))

        try:
            bhSession.close()
        except:
            pass
        sys.exit(1)


if __name__ == '__main__':
    main()