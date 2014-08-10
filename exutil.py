#!/usr/bin/env python
# -*- coding:utf-8 -*-

def has_null_bytes(addr):
	"""
	Checks if an address contains a null byte.
	"""
	has_null_bytes = False
	try:
		str_addr = "0x%08x" % addr
	except ValueError as ve:
		return True
	for i in xrange(2, len(str_addr), 2):
		if str_addr[i:i+2] == "00":
			has_null_bytes = True
			break
	return has_null_bytes

def cmp2(number, word_size=4):
	"""
	Computes the 2's complement for a given number.
	"""
	if (0 <= number <= (2**(word_size * 8 - 1) -1)):
		return number
	else:
		word_size_max = 2**(word_size * 8) - 1
		return -(((abs(number) ^ word_size_max) + 0x1) & word_size_max)

def pad_shellcode(shellcode, pad_char="\x90", word_size=4):
	"""
	Pads a shellcode with pad_char to a word_size boundary 
	"""
	if (len(pad_char) != 1):
		raise ValueError("Padding character must be a single char.")
	padding = word_size - (len(shellcode) % word_size)
	if (padding != 0) and (padding != word_size):
		shellcode += (pad_char * padding)
	return shellcode

def switch_endianness(shellcode, word_size=4):
	"""
	Given a string shellcode, switches the endianness given a specified word_size
	"""
	le_shellcode = ""
	for i in xrange(0, len(shellcode), word_size):
		le_shellcode += shellcode[i:i + word_size][::-1]
	return le_shellcode

def hex_str_repr_2_str(string):
  """
  Takes a hex string representation (ie: "\x41\x42\x43") and returns the corresponding python string
  (ie: "ABC"). None is returns if conversion fails.
  """
  bin_string = None
  try:
    bin_string = string.replace("\\x", "").decode("hex")
  except TypeError as te:
    pass
  return bin_string
