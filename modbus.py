# coding: utf8

import boofuzz
from boofuzz import *
'''
Modbus-TCP boofuzz python

'''
def main():
	target_host = '192.168.0.15'
	target_port = 502

	# tcp_connection = SocketConnection(host=target_host, port=target_port, proto='tcp')
	session = Session(
			target=Target(
				connection=SocketConnection(target_host, target_port, proto='tcp')))



	s_initialize("read_coil_memory")
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('read_coil_memory_block'):
			s_byte(0x01,name='funcCode read coil memory')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
			s_block_end('read_coil_memory_block')
	s_block_end('modbus_head')
	s_repeat("read_coil_memory",min_reps=1,max_reps=255)
	
	

	s_initialize('read_holding_registers')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('read_holding_registers_block'):
			s_byte(0x01,name='read_holding_registers')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
		s_block_end('read_holding_registers_block')
	s_block_end("modbus_head")

	# ---------------------------------------
	s_initialize('ReadDiscreteInputs')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadDiscreteInputsRequest'):
			s_byte(0x02,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
		s_block_end('ReadDiscreteInputsRequest')
	s_block_end("ReadDiscreteInputs")

	# ----------------------------------------
	s_initialize('ReadHoldingRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadHoldingRegistersRequest'):
			s_byte(0x03,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
		s_block_end('ReadHoldingRegistersRequest')
	s_block_end("ReadHoldingRegisters")

	# ----------------------------------------
	s_initialize('ReadInputRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadInputRegistersRequest'):
			s_byte(0x04,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
		s_block_end('ReadHoldingRegistersRequest')
	s_block_end("ReadHoldingRegisters")

	#------------------------------------------
	s_initialize('WriteSingleCoil')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteSingleCoilRequest'):
			s_byte(0x05,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
		s_block_end('WriteSingleCoilRequest')
	s_block_end("WriteSingleCoil")

	#------------------------------------------
	s_initialize('WriteSingleRegister')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteSingleRegisterRequest'):
			s_byte(0x06,name='funcCode',fuzzable=False)
			s_word(0x0000,name='output_address')
			s_word(0x0000,name='output_value')
		s_block_end('WriteSingleCoilRequest')
	s_block_end("WriteSingleRegister")

	#------------------------------------------

	s_initialize('ReadExceptionStatus')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadExceptionStatusRequest'):
			s_byte(0x07,name='funcCode',fuzzable=False)
			#----------------------------------------
		s_block_end('ReadExceptionStatusRequest')
	s_block_end("ReadExceptionStatus")

	#-----------------------------------------
	
	s_initialize('ReadExceptionStatusError')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadExceptionStatusErrorRequest'):
			s_byte(0x87,name='funcCode',fuzzable=False)
			#----------------------------------------
		s_block_end('ReadExceptionStatusErrorRequest')
	s_block_end("ReadExceptionStatusError")

	#---------------------------------------

	'''
		fields_desc = [
		XByteField("funcCode", 0x0F),
		XShortField("startingAddr", 0x0000),
		XShortField("quantityOutput", 0x0001),
		BitFieldLenField("byteCount", None, 8, count_of="outputsValue"),
		FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]
		'''	
	s_initialize('WriteMultipleCoils')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteMultipleCoilsRequest'):
			s_byte(0x0f,name='func_code',fuzzable=False)
			s_word(0x0000,name='starting_address')
			s_dword(0x0000,name='byte_count')
			s_size("outputsValue", length=8)
			if s_block_start("outputsValue"):
				s_word(0x00,name='outputsValue')
				s_block_end()
			s_block_end()
		s_block_end()


	#------------------------------------------------------
	'''
	class ModbusPDU10WriteMultipleRegistersRequest(Packet):
	name = "Write Multiple Registers"
	XByteField("funcCode", 0x10),
	XShortField("startingAddr", 0x0000),
	BitFieldLenField("quantityRegisters", None, 16, count_of="outputsValue",),
	BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x*2),
	FieldListField("outputsValue", [0x0000], XShortField("", 0x0000),
								  count_from=lambda pkt: pkt.byteCount)]


	'''

	s_initialize('WriteMultipleRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteMultipleRegistersRequest'):
			s_byte(0x10,name='func_code',fuzzable=False)
			s_word(0x0000,name='starting_address')
			s_dword(0x0000,name='byte_count')
			s_size("outputsValue",length=16)
			s_size("outputsValue", length=8)
			if s_block_start("outputsValue"):
				s_dword(0x0000,name='outputsValue')
			s_block_end()
		s_block_end()
	s_block_end()

	#-----------------------------------------

	s_initialize('ReportSlaveId')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReportSlaveIdRequest'):
			s_byte(0x11,name='func_code',fuzzable=False)
		s_block_end()
	s_block_end()

	#-----------------------------------------
	s_initialize('ReadFileSub')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadFileSubRequest'):
			s_byte(0x06,name='refType',fuzzable=False)
			s_word(0x0001,name='fileNumber')
			s_word(0x0000,name='recordNumber')
			s_word(0x0000,name='recordLength')
		s_block_end()
	s_block_end()

	#-----------------------------------------
	s_initialize('ReadFileRecord')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadFileRecordRequest'):
			s_byte(0x14,name='funcCode',fuzzable=False)
			s_byte(0x0001,name='byteCount')
		s_block_end()
	s_block_end()

	#-----------------------------------------
	s_initialize('WriteFileSub')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteFileSubRequest'):
			s_byte(0x06,name='refType',fuzzable=False)
			s_word(0x0001,name='fileNumber')
			s_word(0x0000,name='recordNumber')
			# ---------------------------------
			# s_size is record
			s_size('recordData',length=16,name='recordLength')
			if s_block_start("recordData"):
				s_word(0x0000,name='recordData')
			s_word(0x0000,name='recordLength')
		s_block_end()
	s_block_end()

	#------------------------------------------
	s_initialize('WriteFileRecord')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteFileRecordRequest'):
			s_byte(0x15,name='funcCode',fuzzable=False)
			s_byte(0x00,name='datalength')
			# add payload ,random charactic
		s_block_end()
	s_block_end()


	#-------------------------------------------
	s_initialize('MaskWriteRegister')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('MaskWriteRegisterRequest'):
			s_byte(0x96,name='funcCode',fuzzable=False)
			s_word(0x0000,name='refAddr')
			s_word(0xffff,name='andMask')
			s_word(0x0000,name='orMask')
			# add payload ,random charactic
		s_block_end()
	s_block_end()

	#-------------------------------------------
	s_initialize('ReadWriteMultipleRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadWriteMultipleRegistersRequest'):
			s_byte(0x17,name='funcCode',fuzzable=False)
			s_word(0x0000,name='readStartingAddr')
			s_word(0x0001,name='readQuantityRegisters')
			s_word(0x0000,name='writeStartingAddr')
			s_size('writeQuantityRegisters',length=16,endian='>',name="writeQuantityRegisters")
			s_size('writeQuantityRegisters', length=8, endian='>',name="byteCount",math=lambda x:2*x)
			if s_block_start('writeQuantityRegisters'):
				s_size('modbus_head',length=2)
			s_block_end()
		s_block_end()
	s_block_end()




		



		


	session.connect(s_get('modbus_read_coil_memory'))
	session.fuzz()

if __name__ == '__main__':
	main()