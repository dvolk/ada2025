import json
import logging
import subprocess
from app import app, MachineProvider, VirtService, db, Machine
from datetime import datetime


def main(machine_provider_id):
    """
    Checks if the quota has been reached or exceeded by a particular machine provider
    """
    with app.app_context():
        VirtService.set_app(app)

        result = MachineProvider.query.filter_by(id=machine_provider_id).first()

        if type(result.provider_data) == str:
            provider_data = json.loads(result.provider_data)
        else:
            provider_data = result.provider_data

        env = {
            "OS_AUTH_URL": provider_data["auth_url"],
            "OS_USER_DOMAIN_NAME": provider_data["user_domain_name"],
            "OS_PROJECT_DOMAIN_NAME": provider_data["project_domain_name"],
            "OS_USERNAME": provider_data["username"],
            "OS_PASSWORD": provider_data["password"],
        }

        output = subprocess.run(
            ["openstack", "server", "list", "-f", "json"],
            capture_output=True,
            env=env,
        )

        if output.stdout.decode() != "":
            server_list = json.loads(output.stdout.decode())
        else:
            server_list = []

        output = subprocess.run(
            ["openstack", "flavor", "list", "-f", "json"],
            capture_output=True,
            env=env,
        )
        if output.stdout.decode() != "":
            flavor_list = json.loads(output.stdout.decode())
        else:
            flavor_list = []

        instance_count = 0
        active_ram = 0
        active_cpu = 0
        shelved_ram = 0
        shelved_cpu = 0
        other = []
        shelved = []
        shut_down = []
        for instance in server_list:
            if server_list[instance_count]["Status"] == "ACTIVE":
                other.append(server_list[instance_count]["Name"])
                flavor = server_list[instance_count]["Flavor"]
                flavor_count = 0
                for flavors in flavor_list:
                    if (
                        flavor_list[flavor_count]["Name"]
                        == server_list[instance_count]["Flavor"]
                    ):
                        active_ram += flavor_list[flavor_count]["RAM"]
                        active_cpu += flavor_list[flavor_count]["VCPUs"]
                    flavor_count += 1
            elif server_list[instance_count]["Status"] == "SHELVED_OFFLOADED":
                shelved.append(server_list[instance_count]["Name"])
                flavor = server_list[instance_count]["Flavor"]
                flavor_count = 0
                for flavors in flavor_list:
                    if (
                        flavor_list[flavor_count]["Name"]
                        == server_list[instance_count]["Flavor"]
                    ):
                        shelved_ram += flavor_list[flavor_count]["RAM"]
                        shelved_cpu += flavor_list[flavor_count]["VCPUs"]
                    flavor_count += 1
            elif server_list[instance_count]["Status"] == "SHUTOFF":
                shut_down.append(server_list[instance_count]["Name"])
            instance_count += 1

        total_ram = active_ram + shelved_ram
        total_cpu = active_cpu + shelved_cpu

        monitored = datetime.utcnow()

        provider_data.update(
            {
                "active_ram_gb": int(active_ram / 1024),
                "active_cpu": active_cpu,
                "shelved_ram_gb": int(shelved_ram / 1024),
                "shelved_cpu": shelved_cpu,
                "total_ram_gb": int(total_ram / 1024),
                "total_cpu": total_cpu,
                "monitored_date_time": datetime.strftime(
                    monitored, "%Y-%m-%d %H:%M:%S"
                ),
                "machines_shelved": shelved,
                "machines_shut_down": shut_down,
                "machines_other": other,
            }
        )

        provider = db.session.get(MachineProvider, machine_provider_id)
        provider.provider_data = json.dumps(provider_data)
        db.session.commit()
