# coding: utf8
# author: young


import ics_fuzzer.boofuzz
import sys

from ics_fuzzer.boofuzz import *
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
	1: "Read Coils",
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

fileConfig('logging_config.ini')
mylogger = logging.getLogger()
logger = FuzzLogger(fuzz_loggers=[mylogger])


modbus_fuzzer_method = {
	'brute_func_code':1,
}


from fuzz_config import *

def session_create(target_ip, target_port):
	tcp_connection = SocketConnection(host=target_host, port=target_port, proto='tcp')
	session = Session(
	    target=tcp_connection,
		skip = config.skip,
		sleep_time=config.sleep_time,
		restart_interval=config.restart_interval,
		restart_sleep_time=config.restart_sleep_time,
		crash_threshold=config.crash_threshold,
		fuzz_data_logger=config.fuzz_data_logger,
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
	session.
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

def read_holding_registers(session, repeat_reps=[1, 255], fuzz_method=fuzz_method['fuzz_all_block']):
	'''
	send request for reading holding register on PLC via modbus protocol[funccode=0x03]
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
			s_byte( 0x03, name='read_holding_registers' )
			s_word( 0x0000, name='start address' )
			s_word( 0x0000, name='quantity' )
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat('modbus_head',min_reps=repeat_reps[0],max_reps=repeat_reps[1])
	session.connect( s_get( "read_holding_registers" ) )
	session.fuzz()


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
			s_byte( 0x07, name='write_single_register', fuzzable=False)
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
			s_size( 'outputsValue', length=2, fuzzable=False, math=lambda x:x*2,name='byteCount')
			if s_block_start('outputsValue'):
				s_size('byteCount',offset=0,length=2,inclusive=True,fuzzable=True)
			s_block_end('outpus_value')
		s_block_end( 'pdu' )
	s_block_end( "modbus_head" )
	s_repeat( 'modbus_head', min_reps=repeat_reps[0], max_reps=repeat_reps[1] )
	session.connect( s_get( "write_multiple_registers" ) )
	session.fuzz()
'''



'''





'''
config
reading configuration and deploy

'''



	

def main_loop(config):
	'''
	
	:param config: configuration for main_loop
	contains:
		(1)  method for test
	:return:
	'''
	# 1 boundary test
	
	
	# 2 unlisted function code test
	if config.method == 'standard':
		_test_function = function_code_name
		for _id in function_code_name.keys():
			handler_func_name = function_code_handler[_id]
			
	# 3 mixture test by using block repeat
	if config.method == 'mixed':
	
	
	
	
	# 4 packet frame test for packer recv server
	pass
	

if __name__ == '__main__':
	print len( function_code_name.keys() )