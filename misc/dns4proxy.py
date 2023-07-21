"""
This is a DNS server that answers with a round-robin list of proxy ips,
unless the client is in the direct networks list, in which case it
answers with an ip parsed from the hostname.
"""

import itertools
import re
import time
import socket
import os
from ipaddress import ip_network, ip_address

from dnslib import RR, QTYPE, RCODE, parse_time, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

direct_networks = [
    ip_network(n) for n in os.environ.get("DNS4PROXY_DIRECT_NETWORKS", "").split(",")
]
proxies = itertools.cycle(
    [ip for ip in os.environ.get("DNS4PROXY_PROXIES", "").split(",")]
)
domain_regex = os.environ.get("DNS4PROXY_DOMAIN_REGEX", "")


class MyResolver(BaseResolver):
    # regex for matching the DNS query
    regex = re.compile(domain_regex)

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qn = str(qname)
        match_group = self.regex.match(qn)

        client_ip = ip_address(handler.client_address[0])
        if match_group:
            # convert matched groups to IP format
            parsed_ip = ".".join(match_group.groups())

            # validate the parsed IP
            try:
                ip_address(parsed_ip)
            except Exception:
                # If the IP address is invalid, return an NXDOMAIN response
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

            for direct_network in direct_networks:
                if client_ip in direct_network:
                    print(f"resp direct ip: {parsed_ip}")
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(parsed_ip), ttl=60))
                    return reply

            # if client is not in the direct networks, return a proxy
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(next(proxies)), ttl=60))
        else:
            reply.header.rcode = RCODE.NXDOMAIN

        return reply


logger = DNSLogger("request,reply,truncated,error", False)
resolver = MyResolver()
server = DNSServer(
    resolver, port=53, address="0.0.0.0", logger=logger, handler=DNSHandler
)
server.start_thread()

while server.isAlive():
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        break
server.stop()
