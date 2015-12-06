#!/usr/bin/env python3
#encoding: utf-8

from struct import unpack

from .ipv4 import IPv4

class Ethernet():
	"""
		TODO: VLAN_ID and other infos
		
		unpack !
	"""
	dest = None
	src = None
	packet_type = None
	content = None
	raw = None
	payload = None
	mother = None
	
	def __init__(self, packet):
		self.mother = packet
		self.raw = packet.raw
		self.__get_header()
	
	def __get_header(self):
		self.dest = self.__mac_to_str(self.raw[:6])
		self.src = self.__mac_to_str(self.raw[6:12])
		self.packet_type = unpack("H", self.raw[12:14])[0]
		self.payload = self.raw[14:]
		if self.packet_type == 129:
			self.packet_type = unpack("H", self.raw[16:18])[0]
			self.payload = self.raw[18:]
	
	def __mac_to_str(self, mac):
		mac_as_str = ""
		for b in mac:
			if mac_as_str != "":
				mac_as_str += ":"
			mac_as_str += format(b, '02x')
		return mac_as_str
	
	def get_payload(self):
		#is it a IPv4?
		if self.payload[0] >> 4 == 4:
			return IPv4(self.payload)
	
	def __str__(self):
		return "ShortPCAP.Ethernet(dest={},src={},packet_type={})".format(
			self.dest,
			self.src,
			self.packet_type
			)
