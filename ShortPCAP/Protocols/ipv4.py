#!/usr/bin/env python3
#encoding: utf-8

from struct import unpack
from .. import print_hex
from .tcp import TCP
from .udp import UDP

class IPv4():
	"""
		Represents a IPv4 packet
		
		Todos:
			- more detailed view on tos
			- fragment_offset
	"""
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
	
	def __init__(self, raw):
		self.raw = raw
		self.__get_header()
	
	def __get_header(self):
		self.version = self.raw[0] >> 4
		self.ihl = self.raw[0] & 15
		self.tos = self.raw[1]
		self.length = unpack("!H", self.raw[2:4])[0]
		self.identification = unpack("!H", self.raw[4:6])[0]
		self.flags = self.raw[6] >> 4
		self.fragment_offset = self.raw[6:8]
		self.ttl = self.raw[8]
		self.proto = self.raw[9]
		self.header_checksum = self.raw[10:12]
		self.src = self.__beautify_ip(self.raw[12:16])
		self.dest = self.__beautify_ip(self.raw[16:20])
		self.options = self.raw[20:23]
		self.payload = self.raw[self.ihl * 4:]
	
	def __beautify_ip(self, bytes):
		ret_str = ""
		for byte in bytes:
			ret_str += "{}.".format(byte)
		return ret_str[:-1]
		
	
	def __str__(self):
		return "ShortPCAP.IPv4(version={},ihl={},tos={},length={},identification={},flags={},fragment_offset={},ttl={},proto={},header_checksum={},src={},dest={},options={})".format(
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
	
	def get_payload(self):
		if self.proto == 6:
			#TCP
			return TCP(self.payload)
		elif self.proto == 17:
			#UDP
			return UDP(self.payload)
		else:
			raise NotImplementedError("Unknown Protocol")
