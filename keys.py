import os
from io import StringIO

import argh
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from paramiko import WarningPolicy, SSHClient
from scp import SCPClient


def generate_user_keys(prefix):
    """Generate ssh keys for Ada users."""
    key = rsa.generate_private_key(
        backend=crypto_default_backend(), public_exponent=65537, key_size=2048
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption(),
    )

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
    )

    # Add the comment to the end of the public key
    public_key_commented = public_key.decode("utf-8") + " ada-user_" + prefix

    return private_key.decode("utf-8"), public_key_commented


def deploy_user_keys_to_machine(
    hostname, private_key, public_key, authorized_keys, username="ubuntu"
):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(WarningPolicy())
    ssh.connect(hostname, username=username)

    scp = SCPClient(ssh.get_transport())

    try:
        ssh.exec_command("mkdir -p ~/.ssh")
        if private_key:
            scp.putfo(StringIO(private_key), remote_path="~/.ssh/ada-id_rsa")
            ssh.exec_command("chmod 600 ~/.ssh/ada-id_rsa")
        if public_key:
            # Ensure public key ends with a newline
            if not public_key.endswith("\n"):
                public_key += "\n"
            scp.putfo(StringIO(public_key), remote_path="~/.ssh/ada-id_rsa.pub")
            ssh.exec_command("chmod 644 ~/.ssh/ada-id_rsa.pub")
            ssh.exec_command("cat ~/.ssh/ada-id_rsa.pub >> ~/.ssh/authorized_keys")
        if authorized_keys:
            tmp_path = "/tmp/authorized_keys"
            scp.putfo(StringIO(authorized_keys), remote_path=tmp_path)
            ssh.exec_command(
                f"cat {tmp_path} >> ~/.ssh/authorized_keys && rm {tmp_path}"
            )
        ssh.exec_command("chmod 600 ~/.ssh/authorized_keys")
        ssh.exec_command("sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys")
    finally:
        scp.close()
        ssh.close()


if __name__ == "__main__":
    argh.dispatch_commands(
        [
            generate_user_keys,
            deploy_user_keys_to_machine,
        ]
    )
