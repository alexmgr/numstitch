#!/usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function
from argparse import ArgumentParser,ArgumentTypeError
from coinchange import solve_gready, solve_dp
from elfnum import get_numbers, print_results
from exutil import has_null_bytes
from sys import argv, stderr, stdout

def verbose(msg, fd):
	"""
	If the debug flag is active, print message msg  to file descriptor fd
	"""
	if debug:
		print(msg, file=fd)

def parse_arguments():
	"""
	Just argument parsing and housekeeping. Nothing to see.
	"""

	def int_or_hex(string):
		"""
		Returns an integer wheather the input string is a plain integer (123) or in hex format (0x123)
		"""
		try:
			if string.startswith("0x"):
 				number = int(string, 16)
 			else:
				number = int(string)
		except ValueError as ve:
			raise ArgumentTypeError("argument must be a number (hex or int)")
		return number

	parser = ArgumentParser(description="Find individual sum components in a binary which added together provide the number argument.")
	parser.add_argument("filename", help="The binary to analyze")
	parser.add_argument("-n", "--number", help="The number you wish to build from the binary", required=True, type=int_or_hex)
	parser.add_argument("-s", "--section", help="The section you wish to search for numbers in. The default contains all RO sections.", action="append", type=str)
	parser.add_argument("-S", "--segment", help="Use segments instead of sections for the search. Yields more results, but you can get numbers which will change during runtime. If -s i set, use the specified section to retrieve the segment. Default is not to use segments.", action="store_true")
	parser.add_argument("-d", "--duplicates", help="Print all addresses found for a specific number (if more then one). Default is to ignore duplicates and return first match.", action="store_true")
	parser.add_argument("--version", help="Print the program version to screen.", action="version", version="%(prog)s 1.0.0")
	parser.add_argument("-0", "--zero", help="Also print addresses holding the number 0. Default is not to print addresses pointing to 0.", action="store_true")
	parser.add_argument("-e", "--exclude", help="A number to exclude from the calculation set. This flag can be set multiple times. If -0 is not set, 0 is excluded by default.", action="append", type=int_or_hex)
	parser.add_argument("-b", "--nonullbyte", help="Dismiss from calculation numbers which address contains a null byte. Default is to allow null-bytes.", action="store_true")
	parser.add_argument("-v", "--verbose", help="Print debugging information to screen. To ignore errors, redirect stderr to /dev/null.", action="store_true")
	args = parser.parse_args()
	return args

if __name__ == "__main__":
	
	global debug

	args = parse_arguments()
	duplicates = args.duplicates
	change = args.number
	exclude = args.exclude
	no_null_bytes = args.nonullbyte
	debug = args.verbose
	section_names = args.section
	use_segment = args.segment
	print_zero = args.zero
	
	if not print_zero:
		if exclude is not None:
			exclude.append(0)
		else:
			exclude = [0]
	
	if (section_names is None) and (not use_segment):
		section_names = (".interp", ".note.ABI-tag", ".hash", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rel.dyn", ".rel.plt", ".init", ".plt", ".text", ".fini", ".rodata", ".eh_frame", ".comment")
	elif (section_names is None) and use_segment:
		section_names = (".text", ".data")
	
	try:
		f = open(args.filename, "rb")
	except Exception as ex:
		print("Can't open file %s: %s" % (argv[1], ex), file=stderr)
		exit(1)

	candidates = get_numbers(f, section_names, change, exclude, use_segment, no_null_bytes)
	f.close()
	
	if candidates != None:
		unique_values = set(candidates.values())
		#oper, results = solve_dp(list(unique_values), change)

		oper, results = solve_gready(list(unique_values), change)

		if oper != 0:
			print("Found a solution using %u operations: %s" % (oper, results))
		else:
			print("No solution was found. Exiting...", file=stderr)
			exit(2)
	else:
		print("Found no candidate numbers in elf file. Exiting...", file=stderr)
		exit(1)

	print_results(candidates, results, duplicates, print_zero)
	#print(generate_payload(candidates, results))
	exit(0)
	
