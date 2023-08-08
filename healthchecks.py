import paramiko
import time
import logging
from app import app, db, Machine, MachineState

logging.getLogger("paramiko").setLevel(logging.WARNING)

if __name__ == "__main__":
    with app.app_context():
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            machines = Machine.query.filter_by(state=MachineState.READY).all()

            print("\n")

            for machine in machines:
                print(f"{machine.name} (ip={machine.ip}) [id={machine.id}]")
                print("-------")

                client.connect(
                    machine.ip, username=machine.machine_template.os_username
                )

                _, stdout, _ = client.exec_command("systemctl is-active vncserver")
                output = stdout.read().decode()
                print("vncserver: "+ output)

                _, stdout, _ = client.exec_command("systemctl is-active nginx")
                output = stdout.read().decode()
                print("nginx: " + output)

                _, stdout, _ = client.exec_command("systemctl is-active websockify")
                output = stdout.read().decode()
                print("websockify: " + output)

                print("\n")

        except paramiko.AuthenticationException as auth_exc:
            print(f"Authentication failed: {auth_exc}")

        except paramiko.SSHException as ssh_exc:
            print(f"SSH error: {ssh_exc}")

        finally:
            client.close()
