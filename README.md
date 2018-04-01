# boofuzz-modbus
modbus fuzzer based on boofuzz framework.!! Cool 

Recently i use fuzzer for my papers, modbus fuzzer for boofuzz
I only write read_coil_memory packet protocol model.

# first version

## packet protocol list

In modbus protocol specification.list some type of modbus (after list function_code)
1. [OK] read_coil(x01) 
2. read_discrete_inputs(0x02)
3. read_hoding_registers(0x03)
4. read_input_register(0x04)
5. write_single_coil(0x05)
6. write_single_register(0x06)
7. read_exception_status(serial line only)(0x07)
8. diagnostics (Serial Line only)(0x08)
9. get_comm_event_counter(Serial Line only)(0x0b)
10. get_comm_event_log(Serial Line only)(0x0c)
11. write_multiple_coils(0x0f)
12. write_multiple_registers(0x10)
13. report_server_id(Serial Line only)(0x11)
14. read_file_record(0x14)
15. write_file_record(0x15)
16. mask_write_register(0x16)
17. read_write_multiple_registers(0x17)
18. read_fifo_queue(0x18)
19. Encapsulated_interface_transport(0x2b)
......

# usage 

modify target ip address : 127.0.0.1:502
default web ui : http://127.0.0.1:26000

in cmd: python modbus.py 

'''
[2018-04-01 06:00:58,785] Test Case: 180
[2018-04-01 06:00:58,785]     Info: primitive name: "modbus_read_coil_memorys", type: Repeat, default value: 
[2018-04-01 06:00:58,785]     Info: Test case 181 of 181 for this node. 180 of 181 overall.
[2018-04-01 06:00:58,785]   Test Step: Fuzzing Node 'modbus_read_coil_memory'
[2018-04-01 06:00:58,786]     Transmitting 212 bytes: 00 00 00 00 00 06 ff 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 b'\x00\x00\x00\x00\x00\x06\xff\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00'




'''
enjoy your fuzzing ! 
if you have some problem ,contact wechat 

