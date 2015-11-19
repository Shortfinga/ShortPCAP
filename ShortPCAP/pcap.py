#!/usr/bin/env python3
#encoding: utf-8


from struct import unpack
from .packet import Packet

class PCAP():
	"""
		TODO: Swapping!
	"""
	magic_number = None
	version_major = None
	version_minor = None
	thiszone = None
	sigfigs = None
	snaplen = None
	network = None
	packets = None
	
	def __init__(self, pcap_bytes):
		
		self.packets = []
		
		self.__get_header(pcap_bytes[:24])
		self.__get_packets(pcap_bytes[24:])
	
	def __get_header(self, header):
		self.magic_number, self.version_major, self.version_minor, self.thiszone, self.sigfigs, self.snaplen, self.network = unpack('IHHiIII', header)
	
	def __get_packets(self, content):
		file_pointer = 0
		while file_pointer < len(content):
			ts_sec, ts_usec, incl_len, orig_len = unpack("IIII", content[file_pointer:file_pointer+16])
			p = Packet(content[file_pointer+16:file_pointer+16+incl_len])
			p.ts_sec = ts_sec
			p.ts_usec = ts_usec
			p.incl_len = incl_len
			p.orig_len = orig_len
			self.packets.append(p)
			file_pointer = file_pointer+16+incl_len
	
	def __str__(self):
		return "ShortPCAP.PCAP(magic_number={},version_major={},version_minor={},thiszone={},sigfigs={},snaplen={},network={},packets={}".format(
				self.magic_number,
				self.version_major,
				self.version_minor,
				self.thiszone,
				self.sigfigs,
				self.snaplen,
				self.network,
				len(self.packets)
				)
		
