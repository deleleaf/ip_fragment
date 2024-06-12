/*
 * author: deleleaf@gmail.com 
 * with GPL license
 *
 * simple desciption:
 * make ipv4 or ipv6 package reassemble
 * when reassemble complete, modify the ip length and fragment information, 
 * make sure the reassebly package like a package without fragment indication.(but still have fragment header in ipv6)
 *
 * how to use, for example:
 * ------------------------------------------------------------------------------
 *   IPReassembler m_ip_reassembler; //define a object
 *  
 *	 //input_data: orignal package pointer
 *	 //input_len : orignal package length
 *	 //ip_pos    : offset for ip layer in orignal package
 *	 //time_sec  : timestamp, the sec part
 *	 IPReassembler::ReassemblyStatus ip_assemble_r =  m_ip_reassembler.processPacket(input_data, input_len, ip_pos, time_sec);
 *	 
 *	 if(ip_assemble_r == IPReassembler::REASSEMBLING){
 *		 return 0; // this package are preparing to be reassembly
 *	 }
 *	 else if(ip_assemble_r == IPReassembler::REASSEMBLY_COMPLETE){
 *		 ptr_reassembled = m_ip_reassembler.get_reassembled_buff();
 *		 real_buf = ptr_reassembled->fragments;
 *		 uiInputLen = ptr_reassembled->totalSize;
 *		 ip_pos = ptr_reassembled->ip_offset;
 *		 ... // get the reassembly package, and then just deal as common package without fragment
 *		 
 *		 m_ip_reassembler.delete_ressembled_buff(ptr_reassembled); //release the memory
 *	 }
 *	 else if(ip_assemble_r == IPReassembler::COMPLETE_PACKET){
 *		 ... // the input message no need to be reassembly
 *	 }
 * ------------------------------------------------------------------------------------------------------
 */
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <stdio.h>
#include <arpa/inet.h>

#ifndef __IP_FRAGMENT_H__
#define __IP_FRAGMENT_H__

const size_t DEFAULT_BUFFER_SIZE = 4096;
const uint32_t DEFAULT_TIMEOUT = 5; // 默认超时时间，单位秒

class IPReassembler {
public:
	struct ReassemblyBuffer {
	void init(){
		totalSize = 0;
		payload_size = 0;
		ip_offset = 0;
		complete  = false;
		reassembly_header_set_flag = false;
		ipv4_flag	= false;
		payload_of_ip_offset = 0;
		no_more_fragment_flag = false;
		payload_expection_len = 0;
	}
	
	uint8_t  fragments[DEFAULT_BUFFER_SIZE];
	uint16_t totalSize;
	uint16_t payload_size;
	uint16_t ip_offset;
	
	uint32_t timestamp;
	bool	 complete;
	bool	 reassembly_header_set_flag; 
	bool	 ipv4_flag;
	bool	 no_more_fragment_flag;
	uint16_t payload_expection_len;
	uint16_t payload_of_ip_offset;
	
};
private:
    struct FragmentKey {
        uint128_t src;
        uint128_t dst;
        uint32_t id;
        uint8_t protocol;

        bool operator==(const FragmentKey& other) const {
            return src == other.src && dst == other.dst && id == other.id && protocol == other.protocol;
        }
    };

    struct FragmentKeyHasher {
        std::size_t operator()(const FragmentKey& k) const {
            return ((std::hash<uint32_t>()(k.src) ^ (std::hash<uint32_t>()(k.dst) << 1)) >> 1) ^ 
                   (std::hash<uint16_t>()(k.id) << 1) ^ std::hash<uint8_t>()(k.protocol);
        }
    };


    std::unordered_map<FragmentKey, ReassemblyBuffer*, FragmentKeyHasher> reassemblyBuffers;
    size_t   bufferSize;
    uint32_t timeout;
	uint32_t pre_check_time;
	ReassemblyBuffer * m_ptr_valid_buff;

    void removeExpiredFragments(uint32_t current_time){
		if(current_time > pre_check_time && current_time - pre_check_time >= 6){
	        for (auto it = reassemblyBuffers.begin(); it != reassemblyBuffers.end(); ) {
	            if (it->second != NULL && current_time - it->second->timestamp > timeout) {
					delete (it->second);
					it->second = NULL;
	                it = reassemblyBuffers.erase(it);
	            } else {
	                ++it;
	            }
	        }
			pre_check_time = current_time;
		}
	}

public:
    IPReassembler(size_t bufSize = DEFAULT_BUFFER_SIZE, uint32_t timeoutMs = DEFAULT_TIMEOUT)
        : bufferSize(bufSize), timeout(timeoutMs), pre_check_time(0) {}

	~IPReassembler(){}
		
    enum ReassemblyStatus {
        COMPLETE_PACKET,
        REASSEMBLING,
        REASSEMBLY_COMPLETE
    };

	uint32_t get_ressembled_cache_size(){
		uint32_t rsize = reassemblyBuffers.size();
		return rsize;
	}
	
	ReassemblyBuffer* get_reassembled_buff(){
		return m_ptr_valid_buff;
	}

	bool delete_ressembled_buff(ReassemblyBuffer* ptr_node){
		if(ptr_node){
			delete ptr_node;
			ptr_node = NULL;
		}
		return true;
	}
	
    ReassemblyStatus processPacket(uint8_t* packet, uint16_t len, uint16_t ipOffset, uint32_t timestampSec){
	    removeExpiredFragments(timestampSec);

	    bool ipv4 = (packet[ipOffset] >> 4) == 4;
	    uint128_t src, dst;
	    uint32_t id, fragmentOffset;
	    uint8_t protocol;
	    bool moreFragments;
		uint16_t ip_layer_len;
		uint8_t ip_layer_header_len;

	    if (ipv4) {
			ip_layer_header_len =  (packet[ipOffset] & 0x0f)*4;
	        ip_layer_len = ntohs(*reinterpret_cast<uint16_t*>(packet + ipOffset + 2)) - ip_layer_header_len;
	        src = ntohl(*reinterpret_cast<uint32_t*>(packet + ipOffset + 12));
	        dst = ntohl(*reinterpret_cast<uint32_t*>(packet + ipOffset + 16));
	        id = *reinterpret_cast<uint16_t*>(packet + ipOffset + 4);
	        fragmentOffset = (ntohs(*reinterpret_cast<uint16_t*>(packet + ipOffset + 6)) & 0x1FFF) * 8;
	        moreFragments = packet[ipOffset + 6] & 0x20;
	        protocol = packet[ipOffset + 9];
	    } else {
	        // For IPv6, we need to extract the source, destination, and fragment header details
	        ip_layer_header_len = 40;
	        ip_layer_len = ntohs(*reinterpret_cast<uint16_t*>(packet + ipOffset + 4));
			
			for (int i = 0; i < 16; i++)
			{
				src = (src << 8);
				src |= *(packet + ipOffset + 8 + i);
			}
			
			for (int i = 0; i < 16; i++)
			{
				dst = (dst << 8);
				dst |= *(packet + ipOffset + 8 + 16 + i);
			}	
	        //src = *reinterpret_cast<uint128_t*>(packet + ipOffset + 8);
	        //dst = *reinterpret_cast<uint128_t*>(packet + ipOffset + 24);
	        fragmentOffset = 0; // placeholder
	        moreFragments = false; // placeholder
	        protocol = packet[ipOffset + 6];
			if(protocol == 44){// ipv6 extent header for fragment
				protocol 	   = packet[ipOffset + 40];
				fragmentOffset = (ntohs(*reinterpret_cast<uint16_t*>(packet + ipOffset + 42)) & 0xFFF8); // placeholder
				moreFragments  = packet[ipOffset + 43] & 0x01;
				id             = (*reinterpret_cast<uint32_t*>(packet + ipOffset + 44));
				ip_layer_header_len += 8;
			}
	    }

		/*
		 * complete data, directly return
		 */
		if(moreFragments == false && fragmentOffset == 0){
			return COMPLETE_PACKET;
		}

	    FragmentKey key = { src, dst, id, protocol };
		ReassemblyBuffer* pbuff = NULL;
		auto _it = reassemblyBuffers.find(key);
	    if (_it == reassemblyBuffers.end()) {
			pbuff = new ReassemblyBuffer;
			pbuff->init();
			pbuff->timestamp = timestampSec;
			reassemblyBuffers.insert(make_pair(key, pbuff));
	    }
		else{
			pbuff = _it->second;
		}

		/*
		 * check pbuff if valid
		 */
		if(NULL == pbuff){
			return COMPLETE_PACKET; 
		}

		/*
		 * reassembly header setting, like mac+ip
		 */
		if(!pbuff->reassembly_header_set_flag){
			memcpy(pbuff->fragments, packet, ipOffset + ip_layer_header_len);
			pbuff->reassembly_header_set_flag = true;
			pbuff->payload_of_ip_offset = ipOffset + ip_layer_header_len;
			pbuff->totalSize += ipOffset + ip_layer_header_len;
			pbuff->ip_offset = ipOffset;
			if(ipv4){
				pbuff->ipv4_flag = true;
			}
		}

		if(pbuff->payload_of_ip_offset + fragmentOffset + len-ipOffset-ip_layer_header_len <= DEFAULT_BUFFER_SIZE){
			memcpy(pbuff->fragments + pbuff->payload_of_ip_offset + fragmentOffset, packet+ipOffset + ip_layer_header_len, len-ipOffset-ip_layer_header_len);
		}
		pbuff->totalSize += (len-ipOffset-ip_layer_header_len);
		pbuff->payload_size += (len-ipOffset-ip_layer_header_len);

		if(moreFragments == false){
			pbuff->no_more_fragment_flag = true; // just mean the last fragment has been occured. 
			pbuff->payload_expection_len = fragmentOffset + (len-ipOffset-ip_layer_header_len);
		}

		/*
		 * check if reassembe over
		 * this method can avoid the comming pakages out of sequece. 
		 */
		if(pbuff->no_more_fragment_flag == true){
			if(pbuff->payload_expection_len == pbuff->payload_size){
				/*
				 * modify ip layer length and fragment flag
			     */
			    if(pbuff->ipv4_flag){
					uint16_t final_ip_layer_len = pbuff->totalSize - pbuff->ip_offset;
					*((uint16_t*)(pbuff->fragments + pbuff->ip_offset + 2)) = htons(final_ip_layer_len);

					pbuff->fragments[pbuff->ip_offset + 6] = 0x00;
					pbuff->fragments[pbuff->ip_offset + 7] = 0x00;
				}
				else{
					uint16_t final_ip_layer_len = pbuff->totalSize - pbuff->ip_offset - 40;
					*((uint16_t*)(pbuff->fragments + pbuff->ip_offset + 4)) = htons(final_ip_layer_len);

					pbuff->fragments[pbuff->ip_offset + 42] = 0x00;
					pbuff->fragments[pbuff->ip_offset + 43] = 0x00;
				}

				m_ptr_valid_buff = pbuff;
				/*
				 * remove from hashmap
				 */
				if(_it != reassemblyBuffers.end()){
					reassemblyBuffers.erase(_it);
				}
				return REASSEMBLY_COMPLETE;
			}
		}
		
	    return REASSEMBLING;
	}
};


#endif

