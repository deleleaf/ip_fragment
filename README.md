simple desciption:
make ipv4 or ipv6 package reassemble
when reassemble complete, modify the ip length and fragment information, 
make sure the reassebly package like a package without fragment indication.(but still have fragment header in ipv6)

how to use, for example:
------------------------------------------------------------------------------
        #include "ip-fragment.h"
        IPReassembler m_ip_reassembler; //define a object
	IPReassembler::ReassemblyBuffer* ptr_reassembled = NULL; //define a pointer to reassembled buffer
 
	 //input_data: orignal package pointer
	 //input_len : orignal package length
	 //ip_pos    : offset for ip layer in orignal package
	 //time_sec  : timestamp, the sec part
	 IPReassembler::ReassemblyStatus ip_assemble_r =  m_ip_reassembler.processPacket(input_data, input_len, ip_pos, time_sec);
	 
	 if(ip_assemble_r == IPReassembler::REASSEMBLING){
		 return 0; // this package are preparing to be reassembly
	 }
	 else if(ip_assemble_r == IPReassembler::REASSEMBLY_COMPLETE){
		 ptr_reassembled = m_ip_reassembler.get_reassembled_buff();
		 real_buf = ptr_reassembled->fragments;
		 uiInputLen = ptr_reassembled->totalSize;
		 ip_pos = ptr_reassembled->ip_offset;
		 ... // get the reassembly package, and then just deal as common package without fragment
		 
		 m_ip_reassembler.delete_ressembled_buff(ptr_reassembled); //release the memory
	 }
	 else if(ip_assemble_r == IPReassembler::COMPLETE_PACKET){
		 ... // the input message no need to be reassembly
	 }
