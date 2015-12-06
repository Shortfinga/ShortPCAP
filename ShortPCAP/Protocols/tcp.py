#!/usr/bin/env python3
#encoding: utf-8

from struct import unpack
from .. import print_hex

class TCP():
	"""
		Represents a TCP packet
		
		Todos:
			- all
	"""
	source_port = None
	destination_port = None
	seq_number = None
	ack_number = None
	data_offset = None
	reserved = None
	
	
	flag_urg = None
	flag_ack = None
	flag_psh = None
	flag_rst = None
	flag_syn = None
	flag_fin = None
	
	window = None
	checksum = None
	urgent_pointer = None
	options = None
	
	
	raw = None
	payload = None
	
	def __init__(self, raw):
		self.raw = raw
		self.__get_header()
	
	def __get_header(self):
		self.source_port = unpack("!H", self.raw[0:2])[0]
		self.destination_port = unpack("!H", self.raw[2:4])[0]
		self.seq_number = unpack("!I", self.raw[4:8])[0]
		self.ack_number = unpack("!I", self.raw[8:12])[0]
		self.data_offset = self.raw[12] >> 4
		if self.raw[13] & 16 != 0:
			self.flag_ack = True
		if self.raw[13] & 32 != 0:
			self.flag_urg = True
		if self.raw[13] & 8 != 0:
			self.flag_psh = True
		if self.raw[13] & 4 != 0:
			self.flag_rst = True
		if self.raw[13] & 2 != 0:
			self.flag_syn = True
		if self.raw[13] & 1 != 0:
			self.flag_fin = True
		self.window = unpack("!H", self.raw[14:16])[0]
		self.checksum = self.raw[16:18]
		self.urgent_pointer = unpack("!H", self.raw[18:20])[0]
		self.options = self.raw[20:self.data_offset*4]
		self.payload = self.raw[self.data_offset*4:]
		
		
		
		
	
	def get_type(self):
		ret_str = " "
		if self.flag_urg:
			ret_str += "URG "
		if self.flag_ack:
			ret_str += "ACK "
		if self.flag_psh:
			ret_str += "PSH "
		if self.flag_rst:
			ret_str += "RST "
		if self.flag_syn:
			ret_str += "SYN "
		if self.flag_fin:
			ret_str += "FIN "
		return ret_str.strip()
		
	def __str__(self):
		return "ShortPCAP.TCP(source_port={},destination_port={},seq_number={},ack_number={},data_offset={},reserved={},type={},window={},checksum={},urgent_pointer={},options={}".format(
			self.source_port,
			self.destination_port,
			self.seq_number,
			self.ack_number,
			self.data_offset,
			self.reserved,
			self.get_type(),
			self.window,
			self.checksum,
			self.urgent_pointer,
			self.options,
			)
