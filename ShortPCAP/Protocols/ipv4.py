#!/usr/bin/env python3
#encoding: utf-8

from struct import unpack
from bitstring import BitArray

class IPv4():
	version = None
	ihl = None
	tos = None
	length = None
	identification = None
	flags = None
	fragment_offset = None
	ttl = None
	proto = None
	header_checksum = None
	src = None
	dest = None
	options = None
	
	raw = None
	payload = None
	mother = None
	
	def __init__(self, packet):
		self.mother = packet
		self.raw = packet.raw
		self.__get_header()
	
	def __get_header(self):
		print(BitArray(self.raw[0], length=4, offset=0))
	
	def __mac_to_str(self, mac):
		mac_as_str = ""
		for b in mac:
			if mac_as_str != "":
				mac_as_str += ":"
			mac_as_str += format(b, '02x')
		return mac_as_str
	
	def __str__(self):
		return "ShortPCAP.IPv4(version={},ihl={},tos={},length={},identification={},flags={},fragment_offset={},ttl={},header_checksum={},src={},dest={},options={})".format(
			self.version,
			self.ihl,
			self.tos,
			self.length,
			self.identification,
			self.flags,
			self.fragment_offset,
			self.ttl,
			self.proto,
			self.header_checksum,
			self.src,
			self.dest,
			self.options
			)
