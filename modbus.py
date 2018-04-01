# coding: utf8

import boofuzz
from boofuzz import *
'''
Modbus-TCP boofuzz python

'''
def main():
	target_host = '127.0.0.1'
	target_port = 502

	# tcp_connection = SocketConnection(host=target_host, port=target_port, proto='tcp')
	target = Target(
		connection=SocketConnection(target_host, target_port, proto='tcp'))
	
	#target.netmon = pedrpc.Client('192.168.0.131',502)
	# Define Session
	#handle= open('log1.txt','w+')
	#logger = FuzzLogger(fuzz_loggers=fhandle)
	sess = sessions.Session(
		crash_threshold=600,# if reach this threshold , crash will result to the fault
		ignore_connection_aborted=True,
		ignore_connection_reset=True,
	    target=target,
		#fuzz_data_logger=logger
		restart_interval=1000,
		
	)


	s_initialize("modbus_read_coil_memory")
	if s_block_start("modbus_head"):
		s_word(0x0000,name='transId',fuzzable=False)
		s_word(0x0000,name='protoId',fuzzable=False)
		s_word(0x0006,endian='>',name='length',fuzzable=False)
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('modbus_read_coil_memory'):
			s_byte(1,name='funcCode read coil memory',fuzzable=False)
			s_word(0,name='start address',endian='>',fuzzable=False)
			s_word(0,name='quantity',endian='>',fuzzable=True)
		s_block_end()
	s_block_end()
	s_repeat("modbus_read_coil_memory",min_reps=0,max_reps=40,name='modbus_read_coil_memorys')
	mun = s_mutate()
	print '----------'
	print mun
	print '----------'
	sess.connect(sess.root,s_get('modbus_read_coil_memory'))
	sess.fuzz()

if __name__ == '__main__':
	main()
