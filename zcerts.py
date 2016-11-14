# zcerts.py
# 
# Essentially a python wrapper around zmap, ztee and zgrab to avoid clunky
# bash I/O redirect syntax: 
# e.g. zmap [OPTIONS...] | ztee FILE | zgrab [OPTIONS...]
#
# zmap enumerates hosts listening on a given port (e.g. 443) and ztee 
# transforms zmap output for consumption by zgrab. zgrab attempts to 
# establish a TLS connection with the hosts returned by zmap and retrieves 
# the certs sent by the host during the handshake. This script parses the
# verbose output of zgrab.py and isolates just the certificates.

import subprocess
import argparse
import json
import os
import time
from time import asctime
import csv

ZMAP_OUT_DEFAULT = "zmap.out"
ZGRAB_OUT_DEFAULT = "zgrab.out"
ZCERTS_OUT_DEFAULT = "zcerts.out"
ZMAP_OUT = ZMAP_OUT_DEFAULT
ZGRAB_OUT = ZGRAB_OUT_DEFAULT
ZCERTS_OUT = ZCERTS_OUT_DEFAULT

# setup a robust argument parser
# NOTE: there is NO error checking here to make sure that domain names aren't 
# being supplied when the -W or -I flags are being used; if they are the script 
# will behave as if nothing is wrong and SNI support will not be enabled
# TODO: fix the issue outliend by the above note :)
def parse_args():
    parser = argparse.ArgumentParser(description="Utilizes zmap and zgrab " \
        "to enumerate HTTPS hosts and collect their certificate chains")
    parser.add_argument(
        "-p", 
        "--port", 
        metavar="PORT", 
        type=int, 
        help="the port to check for SSL/TLS on")
    parser.add_argument(
        "-i",
        "--interface",
        metavar="IFACE",
        type=str,
        help="the interface for zmap to attempt to use in its scan")
    parser.add_argument(
        "-G",
        "--gateway-mac",
        metavar="MAC",
        type=str,
        help="the MAC of the gateway for a given iface")
    parser.add_argument(
        "-r",
        "--rate",
        metavar="RATE",
        type=int,
        help="send rate in packets/sec")
    parser.add_argument(
        "-B",
        "--bandwidth",
        metavar="BWIDTH",
        type=str,
        help="send rate in bits/sec; support G, M, and K suffixes; "
            "overrides --rate flag")
    parser.add_argument(
        "-b",
        "--blacklist",
        metavar="BLACKLIST",
        type=str,
        help="filepath for blacklisted IPs/IP blocks; defaults to " \
            "/etc/zmap/blacklist.conf")
    parser.add_argument(
        "--zmap-out",
        metavar="ZMAP_OUT",
        type=str,
        help="the file to output the results of the zmap scan to")
    parser.add_argument(
        "--zgrab-out",
        metavar="ZGRAB_OUT",
        type=str,
        help="the file to output the results of the zgrab scan to")
    parser.add_argument(
        "--zcerts-out",
        metavar="ZCERTS_OUT",
        type=str,
        help="the file to output the certs parsed from the zgrab results to")
    ip_subnet_group = parser.add_mutually_exclusive_group()
    ip_subnet_group.add_argument(
        "-N",
        "--in-line",
        metavar="IP_ADDR",
        type=str,
        nargs="+",
        help="the IP(s) to scan; accepts a list of IP addresses or blocks," \
            "inline, in CIDR notation; defaults to the full IPv4 address space")
    ip_subnet_group.add_argument(
        "-w",
        "--whitelist",
        metavar="WHITELIST",
        type=str,
        help="filepath for IPs/subnets to scan (CIDR notation); one " \
            "IP/subnet per line")
    ip_subnet_group.add_argument(
        "-I",
        "--list-ips",
        metavar="LIST_IPS",
        type=str,
        help="filepath for individual IPs (no subnets) to scan; should " \
            "only be used in place of whitelist option when scanning more " \
            "than 10 million individual IPs")
    ip_subnet_group.add_argument(
        "-D",
        "--list-domains",
        metavar="LIST_DOMAINS",
        type=str,
        help="filepath for individual domain names to scan")

    return parser.parse_args()

# generate the bash commands for zmap, ztee and zgrab
def generate_cmd_strings(args, domains=None):
    zmap_cmd = ["sudo", "zmap"]
    
    zmap_cmd.append("-p")
    if args.port:
        zmap_cmd.append(str(args.port))
    else:
        zmap_cmd.append("443")
    
    if args.interface:
        zmap_cmd.append("-i")
        zmap_cmd.append(args.interface)

    if args.gateway_mac:
        zmap_cmd.append("-G")
        zmap_cmd.append(args.gateway_mac)

    if args.rate:
        zmap_cmd.append("-r")
        zmap_cmd.append(str(args.rate))

    if args.bandwidth:
        zmap_cmd.append("-B")
        zmap_cmd.append(args.bandwidth)

    if args.blacklist:
        zmap_cmd.append("-b")
        zmap_cmd.append(args.blacklist)

    zmap_cmd.append("-o");
    zmap_cmd.append("-");

    if args.hosts:
        for host in args.hosts:
            zmap_cmd.append(host)
    elif args.whitelist:
        if not os.path.exists(args.whitelist):
            raise IOError("Path provided for whitelist does not exist")
        zmap_cmd.append("-w")
        zmap_cmd.append(args.whitelist)
    elif args.list_ips:
        if not os.path.exists(args.list_ips):
            raise IOError("Path provided for list of IPs does not exist")
        zmap_cmd.append("-I")
        zmap_cmd.append(args.list_ips)
    elif args.list_domains:
        if domains is None:
            raise ValueError("Improper function call; scanning by domains \
                but no domain list passed as arg")
        for dom in domains:
            zmap_cmd.append(dom)

    ztee_cmd = ["ztee", ZMAP_OUT]

    zgrab_cmd = ["zgrab"]

    zgrab_cmd.append("--port")
    if args.port:
        zgrab_cmd.append(str(args.port))
    else:
        zgrab_cmd.append("443")

    zgrab_cmd.append("--tls")

    zgrab_cmd.append("--output-file=" + ZGRAB_OUT)

    cmds = [zmap_cmd, ztee_cmd, zgrab_cmd]

    return cmds

# for a given list of domain names return a dict mapping them to an IP
def process_domains(domains):
    dom_ip = dict()
    for dom in domains:
        # skip dom if == "" ?
        try:
            ip = socket.gethostbyname(dom)
            dom_ip[dom] = ip
        except:
            print "Failed to resolve domain: %s" % dom
    return dom_ip

# execute zmap, ztee and zgrab
def grab_certs(zmap_cmd, ztee_cmd, zgrab_cmd):
    zmap_proc = subprocess.Popen(zmap_cmd,stdout=subprocess.PIPE)
    ztee_proc = subprocess.Popen(
        ztee_cmd,
        stdin=zmap_proc.stdout,
        stdout=subprocess.PIPE)
    zmap_proc.stdout.close()
    zgrab_proc = subprocess.Popen(zgrab_cmd,stdin=ztee_proc.stdout)
    ztee_proc.stdout.close()
    zgrab_proc.communicate()

# TODO: finish this phase; potentially bypass writing zgrab output directly 
# to file and instead parse as stream and write just certs to file
def process_certs():
    zcerts_out_file = open(ZCERTS_OUT,"a")
    zgrab_out_file = open(ZGRAB_OUT,"r")

    for line in zgrab_out_file:
        line = line.strip()
        if line == "":
            continue
        data = json.loads(line)
        transformed_data = {}
        transformed_data['ip'] = data['ip']
        if "error" in data:
            transformed_data['error'] = True
        else:
            transformed_data['error'] = False
        if 'domain' in data:
            transformed_data['domain'] = data['domain']
        else:
            transformed_data['domain'] = None
        transformed_data['timestamp'] = data['timestamp']
        if not transformed_data['error']:
            transformed_data['certificates'] = {}
            if "chain" in data['data']['tls']['server_certificates']:
                transformed_data['certificates']['chain'] = data['data']['tls']['server_certificates']['chain']
            else:
                transformed_data['certificates']['chain'] = {}
            transformed_data['certificates']['certificate'] = data['data']['tls']['server_certificates']['certificate']

        zcerts_out_file.write(json.dumps(transformed_data)+"\n")

    zcerts_out_file.close()
    zgrab_out_file.close()

# TODO: implement
def grab_certs_batch(zmap_cmd, ztee_cmd, zgrab_cmd, domains):

# perform scans in batches when dealing with domain names
def do_batches(args):
    # open the file of domains to scan
    if not os.path.exists(args.list_domains):
        raise IOError("Path provided for list of domains does not exist")
    with open(args.list_domains,"r") as dom_file:
        count = 0
        domains = []
        # iterate over the file
        for dom in dom_file:
            dom = dom.strip()
            if dom == "":
                continue
            count += 1
            domains.append(dom)
            # perform the scan/grab in batches of 10
            if count % 10 == 0:
                zmap_cmd, ztee_cmd, zgrab_cmd = generate_cmd_strings(args, domains=domains)
                grab_certs_batch(zmap_cmd, ztee_cmd, zgrab_cmd, domains)
                domains = []
        # perform a scan/grab on the remaining domains (in case we don't have a 
        # multiple of 10)
        if len(domains) != 0:
            zmap_cmd, ztee_cmd, zgrab_cmd = generate_cmd_strings(args, domains=domains)
            grab_certs_batch(zmap_cmd, ztee_cmd, zgrab_cmd, domains)

def main():
    global ZMAP_OUT, ZGRAB_OUT, ZCERTS_OUT

    args = parse_args()
    import IPython; IPython.embed()

    if args.zmap_out:
        ZMAP_OUT = args.zmap_out
    if args.zgrab_out:
        ZGRAB_OUT = args.zgrab_out
    if args.zcerts_out:
        ZCERTS_OUT = args.zcerts_out

    if args.list_domains:
        do_batches(args)
    else:
        zmap_cmd, ztee_cmd, zgrab_cmd = generate_cmd_strings(args)
        grab_certs(zmap_cmd, ztee_cmd, zgrab_cmd)
    process_certs()

main()
