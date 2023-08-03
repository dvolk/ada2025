import time
import logging

import paramiko
from paramiko import SSHClient
from scp import SCPClient
import argh


def go(host, username="ubuntu", reboots=2):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username)

    # SCPCLient takes a paramiko transport as its only argument
    scp = SCPClient(ssh.get_transport())

    # This will copy the entire directory at 'machines/ubuntu22_mini'
    # to the user's home directory on the remote host
    logging.warning("copying files")
    scp.put("machines/ubuntu22_mini", recursive=True, remote_path="~/")
    scp.close()

    for i in range(reboots + 1):
        ssh.connect(host, username=username)
        logging.warning(f"starting loop {i}")
        stdin, stdout, stderr = ssh.exec_command(
            "cd ubuntu22_mini && sudo bash setup.bash"
        )
        print(stdout.read().decode())
        print(stderr.read().decode())

        # Wait for some time for the system to reboot
        logging.warning("waiting")
        time.sleep(120)

    scp.close()
    ssh.close()


if __name__ == "__main__":
    argh.dispatch_command(go)
