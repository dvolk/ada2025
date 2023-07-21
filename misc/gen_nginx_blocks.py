from ipaddress import ip_network


def generate_server_block(ip):
    server_name = ip.replace(".", "-") + ".machine.ada.oxfordfun.com"
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
    "172.16.104.0/21",
    "172.16.114.0/24",
    "172.16.112.0/23",
    "172.16.100.0/22",
]

for network in network_list:
    for ip in ip_network(network):
        print(generate_server_block(str(ip)))
