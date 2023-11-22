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

        env = {
            "OS_AUTH_URL": result.provider_data["auth_url"],
            "OS_USER_DOMAIN_NAME": result.provider_data["user_domain_name"],
            "OS_PROJECT_DOMAIN_NAME": result.provider_data["project_domain_name"],
            "OS_USERNAME": result.provider_data["username"],
            "OS_PASSWORD": result.provider_data["password"],
            "OS_PROJECT_NAME": result.provider_data["project_name"],
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

        provider_data = {
            "auth_url": result.provider_data["auth_url"],
            "user_domain_name": result.provider_data["user_domain_name"],
            "project_domain_name": result.provider_data["project_domain_name"],
            "username": result.provider_data["username"],
            "password": result.provider_data["password"],
            "project_name": result.provider_data["project_name"],
            "active_ram_mb": active_ram,
            "active_cpu": active_cpu,
            "shelved_ram_mb": shelved_ram,
            "shelved_cpu": shelved_cpu,
            "total_ram_mb": total_ram,
            "total_cpu": total_cpu,
            "shut_down_instances": shut_down,
            "monitored_date_time": datetime.utcnow(),
        }

        provider = MachineProvider.query.get(machine_provider_id)
        provider.provider_data = provider_data
        db.session.commit()
