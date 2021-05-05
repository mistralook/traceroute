import argparse
import time
from ipwhois import IPWhois, IPDefinedError
from scapy.layers.inet import IP, UDP, TCP, sr1, ICMP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6


class Traceroute:
    def __init__(self):
        self.args = create_parser().parse_args()
        self.host = self.args.IP_ADDRESS
        self.port = int(self.args.port) \
            if self.args.port else self.args.port
        self.timeout = self.args.timeout
        self.num_of_requests = int(self.args.number)
        self.verbose = self.args.verbose
        self.protocol = self.args.protocol
        self.check()

    def sending_packet(self):
        print(f'Трассировка маршрута к {self.host} \n' 
              f'с максимальным числом прыжков {self.num_of_requests}:')
        protocol = self.define_proto()
        for i in range(1, self.num_of_requests + 1):
            if ':' in self.host:
                packet = IPv6(dst=self.host, hlim=i) / protocol
            else:
                packet = IP(dst=self.host, ttl=i) / protocol
            start = time.time()
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            finish = round((time.time() - start) * 1000, 3)
            if reply is None:
                print(str(i) + '.', '*', finish, '*')
                continue
            asn = ''
            if self.verbose:
                try:
                    asn = IPWhois(reply.src).lookup_whois()['asn']
                except IPDefinedError:
                    asn = 'Private-Use Network'
            print(str(i) + '.', reply.src, finish, asn)
            if reply.haslayer(TCP) \
                    or reply.code == 3 or reply.type == 0 \
                    or (reply.code == 4 and reply.type == 1) \
                    or (reply.code == 0 and reply.type == 129):
                print('TRACEROUTE COMPLETED')
                break

    def define_proto(self):
        protocol = None
        if self.protocol == 'udp':
            protocol = UDP(dport=self.port)
        if self.protocol == 'icmp':
            if ':' in self.host:
                protocol = ICMPv6EchoRequest()
            else:
                protocol = ICMP()
        if self.protocol == 'tcp':
            protocol = TCP(dport=self.port)
        return protocol

    def check(self):
        if self.protocol == 'icmp' and self.port:
            raise Exception("ICMP and port can't be together as args")


def main():
    tr = Traceroute()
    tr.sending_packet()


def create_parser():
    ps = argparse.ArgumentParser(prog='traceroute.py',
                                 usage='python %(prog)s '
                                       '[OPTIONS] '
                                       'IP_ADDRESS '
                                       '{tcp|udp|icmp} ')
    ps.add_argument('IP_ADDRESS', help='host address')
    ps.add_argument('-p', '--port', help='port')
    ps.add_argument('-t', '--timeout', help='timeout for response waiting',
                    default=2, type=float)
    ps.add_argument('-n', '--number', default=30,
                    help='max number of requests')
    ps.add_argument('-v', '--verbose',
                    help='show number of autonomous system for every ip',
                    action="store_true")
    ps.add_argument('protocol', help='tcp, udp or icmp protocol')

    return ps


if __name__ == "__main__":
    main()
