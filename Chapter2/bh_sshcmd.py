import sys
import paramiko

# Define global variables
ssh_ip   = '192.168.1.115'
ssh_user = 'root'
ssh_pwd  = 'toor'


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
        ssh_session.exec_command(command)
        print(ssh_session.recv(1024))

    return


if __name__ == '__main__':
    ssh_command(ssh_ip, ssh_user, ssh_pwd, 'id')
