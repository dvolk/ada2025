import argh
from ipaddress import ip_network
import dnscrypto


def generate_server_block(ip, password):
    server_name = dnscrypto.encode_ip(ip, password) + ".machine.ada.oxfordfun.com"
    return f"""
server {{
    listen 443 ssl;
    server_name {server_name};
    ssl_certificate /etc/nginx/keys/machine.ada.oxfordfun.com.fullchain.cer;
    ssl_certificate_key /etc/nginx/keys/machine.ada.oxfordfun.com.key;
    location / {{
        proxy_pass https://{ip};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "keep-alive";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
    """


network_list = [
    "172.16.1.0/24"
]


def main(password):
    for network in network_list:
        for ip in ip_network(network):
            print(generate_server_block(str(ip), password))


if __name__ == "__main__":
    argh.dispatch_command(main)
