import json
import logging
import subprocess

from app import app, MachineProvider, VirtService


def main(machine_provider_id):
    with app.app_context():
        VirtService.set_app(app)

        result = MachineProvider.query.filter_by(id=machine_provider_id).first()
        prov_data = result.provider_data

        env = {
            "OS_AUTH_URL": prov_data["auth_url"],
            "OS_USER_DOMAIN_NAME": prov_data["user_domain_name"],
            "OS_PROJECT_DOMAIN_NAME": prov_data["project_domain_name"],
            "OS_USERNAME": prov_data["username"],
            "OS_PASSWORD": prov_data["password"],
            "OS_PROJECT_NAME": prov_data["project_name"]
        }