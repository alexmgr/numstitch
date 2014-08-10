#!/usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError, ELFParseError
from exutil import has_null_bytes
from struct import unpack, error
from sys import stderr, stdout

def get_numbers(f, section_names, change, exclude = [], use_segment=False, no_null_bytes=False):
	"""
	Iterates over the elf sections or segments in search for numbers smaller than the number change. The function records the
	address at which the number is found, as well as the number itself. A few options control wheather to exclude numbers or 
	addresses. Excluding numbers allows further calculation of the optimal solution to not consider those numbers. A number
	can also be dismissed because it's address contains a null-byte.
	This function returns a dictionary of key addresses to value numbers. Duplicate numbers are conserved in the dictionary. 
	"""
	sections = []
	zones = []
	candidates = {}
	
	try:
		elf = ELFFile(f)
	except (ELFError, ELFParseError) as ex:
		print("Failed to parse elf file %s: %s" % (argv[1], ex), file=stderr)
		return None

	for s in section_names:
		try:
			section = elf.get_section_by_name(s)
			if section != None:
				zones.append(section)
		except (ELFError, ELFParseError) as ex:
			print("Failed to parse elf file %s: %s" % (argv[1], ex), file=stderr)

	if use_segment:
		print("Using segments instead of sections to perform number lookups.", file=stdout)
		print("Using sections [%s] for segment lookup." % ", ".join(section_names), file=stdout)
		segments = []
		for segment in elf.iter_segments():
			for section in zones:
				if segment.section_in_segment(section) and (segment["p_type"] == "PT_LOAD"):
					segments.append(segment)
					print("Found loadable segment starting at [address 0x%08x, offset 0x%08x]" %  (segment["p_vaddr"], segment["p_offset"]), file=stdout)
		zones = segments
	else:
		print("Using sections [%s] to perform number lookups." % ", ".join(section_names), file=stdout)
		
	for zone in zones:
		zone_data = zone.data()
		null_bytes = False
		for i in xrange(0, len(zone_data)):
			try:
				num = unpack("<I", zone_data[i:i+4])
			except error as se:
				print("Reaching end of data. Skipping last bytes...", file=stderr)
			is_excluded = num[0] in exclude if exclude is not None else False
			if no_null_bytes == True:
				if use_segment:
					null_bytes = has_null_bytes(zone["p_vaddr"] + i)
				else:
					null_bytes = has_null_bytes(zone["sh_addr"] + i)
			#if (num[0] <= change) and (num[0] != 0) and (not is_excluded) and (not null_bytes):
			if (num[0] <= change) and (not is_excluded) and (not null_bytes):
				if use_segment:
					candidates[zone["p_vaddr"] + i] = num[0]
				else:
					candidates[zone["sh_addr"] + i] = num[0]
	
	return candidates

def print_results(candidates, results, duplicates=False, print_zero=False):
	"""
	Prints the resulting optimal solution.
	"""
	copy_results = results[::]
	if print_zero:
		copy_results.append(0)
	for k,v in candidates.iteritems():
		for i in enumerate(copy_results):
			if copy_results[i[0]] == v:
				print("0x%08x => 0x%08x %08s" % (k, v, v))
				if not duplicates:
					del copy_results[i[0]]

def generate_payload(candidates, results, stack_frame=0x0804a110):
	copy_results = results[::]
	python_template = """struct.pack("<I", pop_reg1)
struct.pack("<I", 0x%08x)
struct.pack("<I", add_reg2_mem)
"""
	python_code = ""
	for k,v in candidates.iteritems():
		for i in enumerate(copy_results):
 			if copy_results[i[0]] == v:
				python_code += (python_template % k)
				del copy_results[i[0]]
	python_code += """struct.pack("<I", pop_reg1)
struct.pack("<I", 0x%08x)
struct.pack("<I", add_mem_reg2)
""" % stack_frame

	return python_code

