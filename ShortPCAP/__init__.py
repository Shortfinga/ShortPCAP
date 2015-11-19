#!/usr/bin/env python3
#encoding: utf-8

from .pcap import PCAP
from .pcap import Packet

def print_hex(content):
	i = 0
	for b in content:
		if i % 8 == 0 and i != 0:
			print()
		elif i % 4 == 0 and i != 0:
			print(" ", end="")
		#print(hex(b), end=" ")
		print(format(b, '02x'), end=" ")
		i += 1
	print()
