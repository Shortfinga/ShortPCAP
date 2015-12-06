#!/usr/bin/env python3
#encoding: utf-8

import sys
from struct import unpack

from ShortPCAP import PCAP, Packet, print_hex
from ShortPCAP.Protocols import Ethernet, IPv4

if len(sys.argv) < 2:
	print("Usage {} <PCAP-File>".format(sys.argv[0]))
	sys.exit(1)


content = open(sys.argv[1], "rb").read()

p = PCAP(content)
for packet in p.packets:

	e = Ethernet(packet)
	ip = e.get_payload()
	try:
		tcp = ip.get_payload()
		print(tcp)
		#print_hex(tcp.payload)
		print(tcp.payload)
	except NotImplementedError:
		pass
