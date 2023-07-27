import os

import argh
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from paramiko import AutoAddPolicy, SSHClient
from scp import SCPClient


def generate_user_keys(prefix):
    """Generate ssh keys for Ada users.

    This function generates ssh keys for a user, and puts them
    in:
    - ./{prefix}/id_rsa
    - ./{prefix}/id_rsa.pub
    """

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

    os.makedirs(f"./keys/{prefix}", exist_ok=True)

    private_key_path = f"./keys/{prefix}/id_rsa"
    public_key_path = f"./keys/{prefix}/id_rsa.pub"

    with open(private_key_path, "w") as private_key_file:
        private_key_file.write(private_key.decode("utf-8"))

    with open(public_key_path, "w") as public_key_file:
        public_key_file.write(public_key_commented)

    return private_key_path, public_key_path


def deploy_user_keys_to_machine(prefix, hostname, username="ubuntu"):
    key_dir = f"./keys/{prefix}"
    private_key_path = f"{key_dir}/id_rsa"
    public_key_path = f"{key_dir}/id_rsa.pub"
    authorized_keys_path = f"{key_dir}/authorized_keys"

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(hostname, username=username)

    scp = SCPClient(ssh.get_transport())

    try:
        ssh.exec_command("mkdir -p ~/.ssh")
        if os.path.exists(private_key_path):
            scp.put(private_key_path, remote_path="~/.ssh/id_rsa")
            ssh.exec_command("chmod 600 ~/.ssh/id_rsa")
        if os.path.exists(public_key_path):
            scp.put(public_key_path, remote_path="~/.ssh/id_rsa.pub")
            ssh.exec_command("chmod 644 ~/.ssh/id_rsa.pub")
            ssh.exec_command("cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys")
        if os.path.exists(authorized_keys_path):
            tmp_path = "/tmp/authorized_keys"
            scp.put(authorized_keys_path, remote_path=tmp_path)
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
