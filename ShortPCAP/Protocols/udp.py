#!/usr/bin/env python3
#encoding: utf-8

from struct import unpack
from .. import print_hex

class UDP():
	"""
		Represents a UDP packet
	"""
	source_port = None
	destination_port = None
	length = None
	checksum = None
	
	raw = None
	payload = None
	
	def __init__(self, raw):
		self.raw = raw
		self.__get_header()
	
	def __get_header(self):
		self.source_port = unpack("!H", self.raw[0:2])[0]
		self.destination_port = unpack("!H", self.raw[2:4])[0]
		self.length = unpack("!H", self.raw[4:6])[0]
		self.checksum = self.raw[6:8]
		
		self.payload = self.raw[8:self.length]
		
		
	def __str__(self):
		return "ShortPCAP.UDP(source_port={},destination_port={},length={},checksum={})".format(
			self.source_port,
			self.destination_port,
			self.length,
			self.checksum
			)
