# coding: utf8
# author: young

import sys
from boofuzz import *

'''
Modbus-TCP boofuzz python

'''

fuzz_method = {
	'fuzz_all_block':1,
	'fuzz_part_block':2,
	'fuzz_one_block':3,
	'none_fuzz':4
}


# own classes
function_code_name = {
			1 : "Read Coils",
			2 : "Read Discrete Inputs",
			3 : "Read Multiple Holding Registers",
			4 : "Read Input Registers",
			5 : "Write Single Coil",
			6 : "Write Single Holding Register",
			7 : "Read Exception Status",
			8 : "Diagnostic",
			11 : "Get Com Event Counter",
			12 : "Get Com Event Log",
			15 : "Write Multiple Coils",
			16 : "Write Multiple Holding Registers",
			17 : "Report Slave ID",
			20 : "Read File Record",
			21 : "Write File Record",
			22 : "Mask Write Register",
			23 : "Read/Write Multiple Registers",
			24 : "Read FIFO Queue",
			43 : "Read Device Identification"
			}

function_code_handler = {
	1: "read_coil",
	2: "Read Discrete Inputs",
	3: "Read Multiple Holding Registers",
	4: "Read Input Registers",
	5: "Write Single Coil",
	6: "Write Single Holding Register",
	7: "Read Exception Status",
	8: "Diagnostic",
	11: "Get Com Event Counter",
	12: "Get Com Event Log",
	15: "Write Multiple Coils",
	16: "Write Multiple Holding Registers",
	17: "Report Slave ID",
	20: "Read File Record",
	21: "Write File Record",
	22: "Mask Write Register",
	23: "Read/Write Multiple Registers",
	24: "Read FIFO Queue",
	43: "Read Device Identification"
}

#	Supported function codes:
#   	Modsak supported: [1, 2, 3, 4, 5, 6, 7, 8, 11, 15, 16, 17, 22, 23]
#   	Schneider Factory Cast supported: [1, 2, 3, 4, 5, 6, 15, 16, 22, 43, 90]
#
###
import logging
from logging.config import fileConfig

# fileConfig('logging_config.ini')
# mylogger = logging.getLogger()
# logger = FuzzLogger(fuzz_loggers=[mylogger])


modbus_fuzzer_method = {
	'brute_func_code':1,
}


import fuzz_config as config

def session_create(target_ip, target_port, func_name):
	
	target = Target( connection=SocketConnection( target_ip, target_port, proto='tcp' ) )
	# func_logger = logging.basicConfig(
	#
	# )
	
	# logging.basicConfig( level=logging.DEBUG,
	#                      format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
	#                      datefmt='%a, %d %b %Y %H:%M:%S', filename=func_name+'.log', filemode='w' )
	# app_logger = logging.getlogger(func_name)
	session = Session(
	    target= target,
		skip = config.skip,
		sleep_time=config.sleep_time,
		restart_interval=config.restart_interval,
		restart_sleep_time=config.restart_sleep_time,
		crash_threshold=config.crash_threshold,
		fuzz_data_logger=config.fuzz_data_logger,
		logfile=func_name +'.log'
	)

'''

configure for modbus fuzzer

session_filename=None, skip=0, sleep_time=0.0, restart_interval=0, web_port=26000, crash_threshold=3,
             restart_sleep_time=5, fuzz_data_logger=None, check_data_received_each_request=True, log_level=logging.INFO,
             logfile=None, logfile_level=logging.DEBUG, ignore_connection_reset=False, ignore_connection_aborted=False,
             target=None, ):


'''

def read_coil(session, repeat_reps=[1,255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read coil memory on PLC via modbus protocol[funccode=0x01]
	:param session:
	:param repeat_reps:
	:param fuzz_method:
	:return:
	'''
	s_initialize("modbus_read_coil")
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0000,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('pdu'):
			s_byte(0x01,name='funcCode read coil memory',fuzzable=False)
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
		s_block_end('pdu')
	s_block_end('modbus_head')
	s_repeat("modbus_head",min_reps=repeat_reps[0],max_reps=repeat_reps[1])
	session.connect( s_get( "modbus_read_coil" ) )
	session.fuzz()
	
def read_discrete_inputs(session, repeat_reps=[1,255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for reading holding register on PLC via modbus protocol[funccode=0x02]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'read_discrete_inputs' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x02, name='read_holding_registers' )
			s_word( 0x0000, name='start address' )
			s_word( 0x0000, name='quantity' )
		s_block_end( 'pdu' )
	s_block_end("modbus_head")
	
	session.connect( s_get( "read_discrete_inputs" ) )
	session.fuzz()
	
	'''
	class ModbusPDU02ReadDiscreteInputsRequest(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [XByteField("funcCode", 0x02),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

	
	'''


def read_holding_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for reading holding register on PLC via modbus protocol[funccode=0x02]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'read_holding_registers' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x03, name='read_holding_registers' )
			s_word( 0x0000, name='start address' )
			s_word( 0x0000, name='quantity' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	
	session.connect(s_get("read_holding_registers"))
	session.fuzz()
	
	'''
	
	class ModbusPDU03ReadHoldingRegistersRequest(Packet):
    name = "Read Holding Registers"
    fields_desc = [XByteField("funcCode", 0x03),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

    def extract_padding(self, s):
        return b"", None


	'''
#
# def read_holding_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
# 	'''
# 	send request for reading holding register on PLC via modbus protocol[funccode=0x03]
# 	:param session: session to continue fuzz
# 	:param repeat_reps: repeat header times
# 	:param fuzz_method: fuzz type ,fuzz all type ,
# 	:return: test
# 	'''
# 	s_initialize( 'read_discrete_inputs' )
# 	if s_block_start( "modbus_head" ):
# 		s_word( 0x0001, name='transId', fuzzable=False )
# 		s_word( 0x0000, name='protoId', fuzzable=False )
# 		s_word( 0x06, name='length' )
# 		s_byte( 0xff, name='unit Identifier', fuzzable=False )
# 		if s_block_start( 'pdu' ):
# 			s_byte( 0x03, name='read_holding_registers' )
# 			s_word( 0x0000, name='start address' )
# 			s_word( 0x0000, name='quantity' )
# 		s_block_end( 'pdu' )
# 	s_block_end( "modbus_head" )
# 	s_repeat('modbus_head',min_reps=repeat_reps[0],max_reps=repeat_reps[1])
# 	session.connect( s_get( "read_holding_registers" ) )
# 	session.fuzz()


def read_input_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read input registers on PLC via modbus protocol[funccode=0x04]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'read_input_registers' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x04, name='read_holding_registers', fuzzable=False)
			s_word( 0x0000, name='start address' )
			s_word( 0x0000, name='quantity' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_input_registers" ) )
	session.fuzz()
	
	'''
	class ModbusPDU04ReadInputRegistersRequest(Packet):
    name = "Read Input Registers"
    fields_desc = [XByteField("funcCode", 0x04),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

	class ModbusPDU05WriteSingleCoilRequest(Packet):
    name = "Write Single Coil"
    fields_desc = [XByteField("funcCode", 0x05),
                   XShortField("outputAddr", 0x0000),  # from 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 == Off, 0xFF00 == On

	
	'''


def write_single_coil(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write single coil on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'write_single_coil' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x05, name='write_single_coil', fuzzable=False)
			s_word( 0x0000, name='outputAddr' ) # from 0x0000 to 0xFFFF
			s_word( 0x0000, name='outputValue' ) # 0x0000 == Off, 0xFF00 == On
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_single_coil" ) )
	session.fuzz()
	
'''
class ModbusPDU06WriteSingleRegisterRequest(Packet):
    name = "Write Single Register"
    fields_desc = [XByteField("funcCode", 0x06),
                   XShortField("registerAddr", 0x0000),
                   XShortField("registerValue", 0x0000)]

    def extract_padding(self, s):
        return b"", None


'''
def write_single_register(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_single_register on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'write_single_register' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x06, name='write_single_register', fuzzable=False)
			s_word( 0x0000, name='registerAddr' ) # from 0x0000 to 0xFFFF
			s_word( 0x0000, name='registerValue' ) # 0x0000 == Off, 0xFF00 == On
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_single_register" ) )
	session.fuzz()

def read_exception_status(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_exception_status on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'read_exception_status' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x07, name='read_exception_status', fuzzable=False)
			s_random(0,1,16)
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'read_exception_status', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_exception_status" ) )
	session.fuzz()
	
	
'''
class ModbusPDU0FWriteMultipleCoilsRequest(Packet):
    name = "Write Multiple Coils"
    fields_desc = [XByteField("funcCode", 0x0F),
                   XShortField("startingAddr", 0x0000),
                   XShortField("quantityOutput", 0x0001),
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue"),
                   FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]

'''
def write_multiple_coils(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_multiple_coils on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	'''
	s_initialize( 'write_multiple_coils' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x0f, name='write_multiple_coils', fuzzable=False )
			s_word( 0x0000, name='startingAddr' )  # from 0x0000 to 0xFFFF
			s_word( 0x0001, name='quantityOutput' )  # 0x0000 == Off, 0xFF00 == On
			s_size('outputs_value',offset=0,length=2,inclusive=True,fuzzable=True)
			if s_block_start('outputs_value'):
				s_size('modbus_head',offset=0,length=1,inclusive=True,fuzzable=True)
			s_block_end('outpus_value')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'read_exception_status', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_exception_status" ) )
	session.fuzz()
	
	'''
	class ModbusPDU10WriteMultipleRegistersRequest(Packet):
    name = "Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startingAddr", 0x0000),
                   BitFieldLenField("quantityRegisters", None, 16, count_of="outputsValue",),
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x*2),
                   FieldListField("outputsValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]
	
	:return:
	'''


def write_multiple_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_multiple_coils on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test
	
	class ModbusPDU10WriteMultipleRegistersRequest(Packet):
    name = "Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startingAddr", 0x0000),
                   BitFieldLenField("quantityRegisters", None, 16, count_of="outputsValue",),
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x*2),
                   FieldListField("outputsValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]
	
	:return:
	'''
	
	s_initialize( 'write_multiple_registers' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x0f, name='write_multiple_registers', fuzzable=False )
			s_word( 0x0000, name='startingAddr' )
			s_size( 'outputsValue', length=2, fuzzable=False, name='quantityRegisters')
			s_size( 'outputsValue', length=1, fuzzable=False, math=lambda x:x*2,name='byteCount')
			if s_block_start('outputsValue'):
				s_size('byteCount',offset=0,length=2,inclusive=True,fuzzable=True)
			s_block_end('outpus_value')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_multiple_registers" ) )
	session.fuzz()


def report_slave_id(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for report_slave_id on PLC via modbus protocol[funccode=0x11]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test

	class ModbusPDU11ReportSlaveIdRequest(Packet):
    name = "Report Slave Id"
    fields_desc = [XByteField("funcCode", 0x11)]

    def extract_padding(self, s):
        return b"", None

	:return:
	'''
	
	s_initialize( '' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x11, name='report_slave_id', fuzzable=False )
			s_random(0, max_length= 4,min_length=1)
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "report_slave_id" ) )
	session.fuzz()

'''report_slave_id

class ModbusReadFileSubRequest(Packet):
    name = "Sub-request of Read File Record"
    fields_desc = [ByteField("refType", 0x06),
                   ShortField("fileNumber", 0x0001),
                   ShortField("recordNumber", 0x0000),
                   ShortField("recordLength", 0x0001)]




'''


def read_file_sub(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_file_sub on PLC via modbus protocol[funccode=0x11]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type

	:return:
	
	
	class ModbusReadFileSubRequest(Packet):
    name = "Sub-request of Read File Record"
    fields_desc = [ByteField("refType", 0x06),
                   ShortField("fileNumber", 0x0001),
                   ShortField("recordNumber", 0x0000),
                   ShortField("recordLength", 0x0001)]

	
	
	
	'''
	
	s_initialize( 'read_file_sub' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x06, name='read_file_sub', fuzzable=False )
			s_word( 0x0001 , name='fileNumber')
			s_word( 0x0000 , name='recordNumber')
			s_word( 0x0000 , name='recordlength')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	#s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_file_sub" ) )
	session.fuzz()


def read_file_record(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_multiple_coils on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test

	class ModbusPDU14ReadFileRecordRequest(Packet):
    name = "Read File Record"
    fields_desc = [XByteField("funcCode", 0x14),
                   ByteField("byteCount", None)]

	:return:
	'''
	
	s_initialize( 'read_file_record' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x14, name='read_file_record', fuzzable=False )
			s_byte(0x00,name='byteCount')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_file_record" ) )
	session.fuzz()


def write_file_sub(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_multiple_coils on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return:
	
	
	# 0x15 : Write File Record
	class ModbusWriteFileSubRequest(Packet):
    name = "Sub request of Write File Record"
    fields_desc = [ByteField("refType", 0x06),
                   ShortField("fileNumber", 0x0001),
                   ShortField("recordNumber", 0x0000),
                   BitFieldLenField("recordLength", None, 16, length_of="recordData", adjust=lambda pkt, p: p//2),
                   FieldListField("recordData", [0x0000], ShortField("", 0x0000),
                                  length_from=lambda pkt: pkt.recordLength*2)]
	'''
	
	s_initialize( 'write_file_sub' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x06, name='refType', fuzzable=False )
			s_word( 0x0001, name='file_number' )
			s_word( 0x0000, name='record_number')
			s_size( 'record_data', length=2, fuzzable=False, name='record_length' ,math =lambda x:x/2)
			if s_block_start( 'record_data' ):
				s_size( 'record_length', offset=0, length=2, inclusive=True, fuzzable=True,math=lambda x:x*2,name='record_data')
			s_block_end( 'record_data' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_file_sub" ) )
	session.fuzz()


def write_file_record(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for write_multiple_coils on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return:


	class ModbusPDU15WriteFileRecordRequest(Packet):
    name = "Write File Record"
    fields_desc = [XByteField("funcCode", 0x15),
                   ByteField("dataLength", None)]

	'''
	
	s_initialize( 'write_file_record' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x15, name='refType', fuzzable=False )
			s_byte( 0x00, name='data_length')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_file_record" ) )
	session.fuzz()


def mask_write_register(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for MaskWriteRegister on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return:
	class ModbusPDU16MaskWriteRegisterRequest(Packet):
    # and/or to 0xFFFF/0x0000 so that nothing is changed in memory
    name = "Mask Write Register"
    fields_desc = [XByteField("funcCode", 0x16),
                   XShortField("refAddr", 0x0000),
                   XShortField("andMask", 0xffff),
                   XShortField("orMask", 0x0000)]
	

	'''
	s_initialize( 'mask_write_register' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x16, name='mask_write_register', fuzzable=False )
			s_word( 0x0001, name='refAddr' )
			s_word( 0xffff, name='andMask' )
			s_word( 0x0000, name='orMask'  )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "mask_write_register" ) )
	session.fuzz()


def read_write_multiple_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_write_multiple_registers on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test

	class ModbusPDU17ReadWriteMultipleRegistersRequest(Packet):
    name = "Read Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x17),
                   XShortField("readStartingAddr", 0x0000),
                   XShortField("readQuantityRegisters", 0x0001),
                   XShortField("writeStartingAddr", 0x0000),
                   BitFieldLenField("writeQuantityRegisters", None, 16, count_of="writeRegistersValue"),
                   BitFieldLenField("byteCount", None, 8, count_of="writeRegistersValue", adjust=lambda pkt, x: x*2),
                   FieldListField("writeRegistersValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]

	:return:
	'''
	
	s_initialize( 'read_write_multiple_registers' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x17, name='read_write_multiple_registers', fuzzable=False )
			s_word( 0x0000, name='readStartingAddr' )
			s_word( 0x0001, name='readQuantityRegisters' )
			s_word( 0x0000, name='writeStartingAddr' )
			s_size( 'writeRegistersValue', length=2, fuzzable=False, name='writeQuantityRegisters' )
			s_size( 'writeRegistersValue', length=1, fuzzable=False, math=lambda x: x * 2, name='byteCount' )
			if s_block_start( 'writeRegistersValue' ):
				s_size( 'byteCount', offset=0, length=2, inclusive=True, fuzzable=True )
			s_block_end( 'writeRegistersValue' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_write_multiple_registers" ) )
	session.fuzz()


def read_FIFO_queue(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_write_multiple_registers on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test


class ModbusPDU18ReadFIFOQueueRequest(Packet):
    name = "Read FIFO Queue"
    fields_desc = [XByteField("funcCode", 0x18),
                   XShortField("FIFOPointerAddr", 0x0000)]

	:return:
	'''
	
	s_initialize( 'read_FIFO_queue' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x18, name='read_FIFO_queue', fuzzable=False )
			s_word( 0x0000, name='FIFOPointerAddr' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_FIFO_queue" ) )
	session.fuzz()


def read_device_identification(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_write_multiple_registers on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test

	class ModbusPDU2B0EReadDeviceIdentificationRequest(Packet):
    name = "Read Device Identification"
    fields_desc = [XByteField("funcCode", 0x2B),
                   XByteField("MEIType", 0x0E),
                   ByteEnumField("readCode", 1, _read_device_id_codes),
                   ByteEnumField("objectId", 0x00, _read_device_id_object_id)]

	:return:
	'''
	
	# 0x2B/0x0E - Read Device Identification values
	_read_device_id_codes = {1: "Basic", 2: "Regular", 3: "Extended", 4: "Specific"}
	# 0x00->0x02: mandatory
	# 0x03->0x06: optional
	# 0x07->0x7F: Reserved (optional)
	# 0x80->0xFF: product dependent private objects (optional)
	_read_device_id_object_id = {0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision", 0x03: "VendorUrl",
	                             0x04: "ProductName", 0x05: "ModelName", 0x06: "UserApplicationName"}
	
	s_initialize( 'read_device_identification' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x2b, name='read_device_identification', fuzzable=False )
			s_byte( 0x0e, name='MEIType', fuzzable=False)
			s_group(name='readCode',values=_read_device_id_codes.keys())
			s_group(name='objectId',values=_read_device_id_object_id.keys())
			s_word( 0x0000, name='FIFOPointerAddr' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "read_device_identification" ) )
	session.fuzz()


def reserved_function_Code(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for read_write_multiple_registers on PLC via modbus protocol[funccode=0x05]
	:param session: session to continue fuzz
	:param repeat_reps: repeat header times
	:param fuzz_method: fuzz type ,fuzz all type ,
	:return: test


	class ModbusPDUReservedFunctionCodeRequest(Packet):
    name = "Reserved Function Code Request"
    fields_desc = [
            ByteEnumField("funcCode", 0x00, _reserved_funccode_request),
            StrFixedLenField('payload', '', 255), ]

	:return:
	'''
	
	s_initialize( 'reserved_function_Code' )
	if s_block_start( "modbus_head" ):
		s_word( 0x0001, name='transId', fuzzable=False )
		s_word( 0x0000, name='protoId', fuzzable=False )
		s_word( 0x06, name='length' )
		s_byte( 0xff, name='unit Identifier', fuzzable=False )
		if s_block_start( 'pdu' ):
			s_byte( 0x2b, name='reserved_function_Code', fuzzable=False )
			s_string('a'*255)
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "reserved_function_Code" ) )
	session.fuzz()


'''
config
reading configuration and deploy

'''
def main_test():
	import fuzz_config
	test = dir( fuzz_method )
	print fuzz_method



def main_loop():
	'''
	
	:param config: configuration for main_loop
	contains:
		(1)  method for test
	:return:
	'''
	# 1 boundary test
	if config.method == 0:
		pass
	
	# 2 unlisted function code test
	if config.method == 1: # standart test
		_test_function = function_code_name
		for _id in function_code_name.keys():
			handler_func_name = function_code_handler[_id]
			
	# 3 mixture test by using block repeat
	if config.method == '2':
		pass
	

	
	
	
	
	
	
	# 4 packet frame test for packer recv server
	pass
	

if __name__ == '__main__':
	main_test()