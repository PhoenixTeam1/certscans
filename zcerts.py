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

ZMAP_OUT_DEFAULT = "zmap.out"
ZGRAB_OUT_DEFAULT = "zgrab.out"
ZCERTS_OUT_DEFAULT = "zcerts.out"

# setup a robust argument parser
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
		type=int,
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
		"-H",
		"--hosts",
		metavar="HOST",
		type=str,
		nargs="+",
		help="the IP(s) to scan; accepts a list of IP addresses or blocks" \
			"in CIDR notation; defaults to the full IPv4 address space")
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

	return parser.parse_args()

# generate the bash commands for zmap, ztee and zgrab
def generate_cmd_strings(args):
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
		zmap_cmd.append(str(args.bandwidth))

	if args.blacklist:
		zmap_cmd.append("-b")
		zmap_cmd.append(args.blacklist)

	zmap_cmd.append("-o");
	zmap_cmd.append("-");

	if args.hosts:
		for host in args.hosts:
			zmap_cmd.append(host)

	ztee_cmd = ["ztee"]

	if args.zmap_out:
		ztee_cmd.append(args.zmap_out)
	else:
		ztee_cmd.append(ZGRAB_OUT_DEFAULT)

	zgrab_cmd = ["zgrab"]

	zgrab_cmd.append("--port")
	if args.port:
		zgrab_cmd.append(str(args.port))
	else:
		zgrab_cmd.append("443")

	zgrab_cmd.append("--tls")

	if args.zgrab_out:
		zgrab_out_filename = args.zgrab_out
	else:
		zgrab_out_filename = ZGRAB_OUT_DEFAULT
	zgrab_cmd.append("--output-file=" + zgrab_out_filename)

	cmds = [zmap_cmd, ztee_cmd, zgrab_cmd]

	return cmds

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
# def process_certs(zcerts_out_filename):
	# zcerts_out_file = open(zcerts_out_filename,"w")

def main():
	args = parse_args()
	zmap_cmd, ztee_cmd, zgrab_cmd = generate_cmd_strings(args)
	grab_certs(zmap_cmd, ztee_cmd, zgrab_cmd)
	# process_certs(args.zcerts_out)

main()
