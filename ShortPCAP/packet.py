#!/usr/bin/env python3
#encoding: utf-8


class Packet():
	ts_sec = None
	ts_usec = None
	incl_len = None
	orig_len = None
	raw = None
	
	def __init__(self, b):
		self.raw = b
	
	def __str__(self):
		return "ShortPCAP.Packet(ts_sec={},ts_usec={},incl_len={},orig_len={})".format(
			self.ts_sec,
			self.ts_usec,
			self.incl_len,
			self.orig_len
			)
