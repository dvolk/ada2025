"""
This is a DNS server that answers with a round-robin list of proxy ips,
unless the client is in the direct networks list, in which case it
answers with an ip parsed from the hostname.
"""

import time
from ipaddress import ip_network, ip_address
import random
import logging
from logging.handlers import TimedRotatingFileHandler

import yaml
from dnslib import RR, QTYPE, RCODE, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
import argh

import dnscrypto


class Network:
    def __init__(self, name, resolved_networks, direct_networks, proxy_ips):
        self.name = name
        self.resolved_networks = [ip_network(ipnet) for ipnet in resolved_networks]
        self.direct_networks = [ip_network(ipnet) for ipnet in direct_networks]
        self.proxy_ips = proxy_ips

    def is_ip_in_direct_network(self, ip):
        ip = ip_address(ip)
        for subnet in self.direct_networks:
            if ip in subnet:
                return True
        return False


class Config:
    def __init__(self, filename):
        with open(filename) as f:
            config = yaml.safe_load(f)
        print(config)
        self.networks = [Network(**c) for c in config["networks"]]
        self.networks_by_name = {n.name: n for n in self.networks}
        self.networks_by_resolved_subnet = {}
        for n in self.networks:
            for rn in n.resolved_networks:
                self.networks_by_resolved_subnet[rn] = n

    def network_from_resolved_ip(self, ip):
        ip = ip_address(ip)
        for subnet, net in self.networks_by_resolved_subnet.items():
            if ip in subnet:
                return net
        return None


config = Config("dns4proxy.conf")


class MyResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qn = str(qname)

        parsed_host = qn[0:13].lower()
        client_ip = ip_address(handler.client_address[0])

        try:
            parsed_ip = dnscrypto.decode_ip(parsed_host, PASSWORD)
        except Exception as e:
            logging.warning(f"no decoded ip for {parsed_host}: {str(e)}")
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        # validate the parsed IP
        try:
            ip_address(parsed_ip)
        except Exception:
            logging.warning(f"bad decoded ip for {parsed_ip}")
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        net = config.network_from_resolved_ip(parsed_ip)

        if not net:
            logging.warning(f"no network for ip for {parsed_ip}")
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        if net.is_ip_in_direct_network(client_ip):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(parsed_ip), ttl=60))
        else:
            proxy_ip = random.choice(net.proxy_ips)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(proxy_ip), ttl=60))

        return reply


def logf(s):
    logger = logging.getLogger()
    print(s)
    logger.info(s)


def main(password):
    global PASSWORD
    PASSWORD = password

    # Set up logging to file
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # specify the level of logging details

    # Create a TimedRotatingFileHandler for the logger
    handler = TimedRotatingFileHandler(
        "logfile.log", when="D", interval=1, backupCount=90
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))

    logger.addHandler(handler)

    logger = DNSLogger("request,reply,truncated,error", False, logf=logf)
    resolver = MyResolver()
    server = DNSServer(
        resolver, port=5353, address="0.0.0.0", logger=logger, handler=DNSHandler
    )
    server.start_thread()

    while server.isAlive():
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
    server.stop()


if __name__ == "__main__":
    argh.dispatch_command(main)
