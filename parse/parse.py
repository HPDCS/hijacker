#!/bin/python

import sys

class AddressInfo():
	def __init__(self, address):
		self.foo = {}
		self.full_access = 0
		self.partial_access = 0
		self.address = address
	
	def addPartial(self, acc):
		self.partial_access = acc
		
	def addFull(self, acc):
		self.full_access = acc
		
	def __str__(self):
		return "addr: " + hex(self.address) + "\t full access: " + str(self.full_access) + "\t partial access: " + str(self.partial_access) + "\n"
			

class BlockInfo():
	def __init__(self, block):
		self.block = block
		self.addresses = {}
		
	def setPartialInfo(self, address, count):
		if address in self.addresses:
			addr = self.addresses[address]
		else:
			self.addresses[address] = AddressInfo(address)
			addr = self.addresses[address]
		addr.addPartial(count)
		
	def setFullInfo(self, address, count):
		if address in self.addresses:
			addr = self.addresses[address]
		else:
			self.addresses[address] = AddressInfo(address)
			addr = self.addresses[address]
		addr.addFull(count)
		
	def dump(self):
		taken = 0
		all_count = 0
		full_measure = 0
		part_measure = 0
		for the_addr in self.addresses:
			addr = self.addresses[the_addr]
			if addr.partial_access > 0:
				taken += 1
			all_count += 1
			full_measure += addr.full_access
			part_measure += addr.partial_access
		return str(self.block) + "\t" + str(float(taken) / float(all_count)) + "\t" + str(float(part_measure) / float(full_measure)) + "\n"
		
	def __str__(self):
		represent = "Block: " + str(self.block)
		for the_addr in self.addresses:
			represent += "\t" + str(self.addresses[the_addr])
		represent += "\n"
		return represent
			
	def __repr__(self):
		return self.__str__()


if len(sys.argv) < 4:
	print "Usage: " + sys.argv[0] + " <partial trace> <full trace> <outfile>"
	sys.exit()
	
blocks = {}

partial_f = [line.rstrip('\n') for line in open(sys.argv[1])]
full_f = [line.rstrip('\n') for line in open(sys.argv[2])]

for part_elem in partial_f:
	line = part_elem.split()
	address = long(line[0], 16) # hex value
	count = long(line[1])
	block_id = long(line[2])
	if block_id in blocks:
		block = blocks[block_id]
	else:
		blocks[block_id] = BlockInfo(block_id)
		block = blocks[block_id]

	block.setPartialInfo(address, count)
	
for part_elem in full_f:
	line = part_elem.split()
	address = long(line[0], 16) # hex value
	count = long(line[1])
	block_id = long(line[2])
	if block_id in blocks:
		block = blocks[block_id]
	else:
		blocks[block_id] = BlockInfo(block_id)
		block = blocks[block_id]

	block.setFullInfo(address, count)

# This is just for debugging
print blocks

# Dump data
f = open(sys.argv[3],'w')
for block_id in blocks:
	block = blocks[block_id]
	f.write(block.dump())
f.close()
