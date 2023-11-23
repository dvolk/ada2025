import json
import logging
import subprocess
from app import app, MachineProvider, VirtService, db
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

        server_list = json.loads(output.stdout.decode())

        output = subprocess.run(
            ["openstack", "flavor", "list", "-f", "json"],
            capture_output=True,
            env=env,
        )

        flavor_list = json.loads(output.stdout.decode())

        instance_count = 0
        active_ram = 0
        active_cpu = 0
        shelved_ram = 0
        shelved_cpu = 0
        shut_down = []
        for instance in server_list:
            if server_list[instance_count]["Status"] == "ACTIVE":
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

        provider_data.update(
            {
                "active_ram_gb": int(active_ram / 1024),
                "active_cpu": active_cpu,
                "shelved_ram_gb": int(shelved_ram / 1024),
                "shelved_cpu": shelved_cpu,
                "total_ram_gb": int(total_ram / 1024),
                "total_cpu": total_cpu,
                "shut_down_instances": shut_down,
                "monitored_date_time": str(
                    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                ),
            }
        )

        provider = MachineProvider.query.get(machine_provider_id)
        provider.provider_data = provider_data
        db.session.commit()

