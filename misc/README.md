# ada2025 misc

## maintenance.html

To display page when we're doing maintenance.

put this into `/var/www/html`, edit `nginx.conf` by uncommenting the maintenance block and commenting the usual / location.

## gen_nginx_blocks.py

Generate nginx server blocks for a proxy into private stfc network.

i.e. proxy `encoded_ip_here.machine.ada.oxfordfun.com` to `172.16.104.12`

## dns4proxy.py

This is a DNS server that answers with a round-robin list of proxy ips, unless the client is in the direct networks list, in which case it answers with an ip parsed from the hostname.

### Motivation
If you want to access many hosts behind a firewall, you can set up public nginx proxies that have access to the hosts

But if the client is also behind the firewall, you'd prefer to connect directly

In the example below, if you're behind the firewall (direct networks), `encoded_1-2-3-4-ip.dynamic.yourdomain.com` will return `1.2.3.4`

but if you're in front of the firewall, it will return one of the proxies.

You can use nginx to parse the IP from the hostname and proxy the traffic to the correct internal IP

Note that the IPs in the hostname are encoded to prevent enumeration.
