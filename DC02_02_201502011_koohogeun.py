import socket
import struct

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header =  "0x" + ethernet_header[12].hex()

	print("======ethernet header======")
	print("src_mac_address : ", ether_src)
	print("dest_mac_address : ", ether_dest)
	print("ip_version", ip_header)


def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

def parsing_IP_header(data):
	ip_header = struct.unpack("!1b1b1h1H1H1B1B2s4B4B", data)
	ip_ver = int(ip_header[0]/16)
	ip_len = int(ip_header[0]%16)
	dsc = ip_header[1]
	ecn = ip_header[1]
	total_l = ip_header[2]
	idf = ip_header[3]
	flg = hex(ip_header[4])
	res_b = int(ip_header[4]/(2**15))
	not_f = int(ip_header[4]/(2**14))%2
	frag = int(ip_header[4]/(2**13))%2
	frag_off = int(ip_header[4]%(2**13))
	TTL = ip_header[5]
	prc = ip_header[6]
	hck = "0x" + ip_header[7].hex()
	src = convert_ip_address(ip_header[8:12])
	dst = convert_ip_address(ip_header[12:16])

	print("=========ip_header==========")
	print("ip_version: ", ip_ver)
	print("ip_Length: ", ip_len)
	print("differentiated_service_codepoint: ", int(dsc) + int(ecn/4))
	print("explicit_congestion_notification: ", int(ecn%4))
	print("total_length: ", total_l)
	print("identification ", idf)
	print("flags: ", flg)
	print(">>>reserved_bit: ", res_b)
	print(">>>not_fragments: ", not_f)
	print(">>>fragments: ", frag)
	print(">>>fragments_offset: ", frag_off)
	print("Time to live: ", TTL)
	print("protocol: ", prc)
	print("header checksum: ", hck)
	print("source_ip_address: ", src)
	print("dest_ip_address: ", dst)
	return prc


def convert_ip_address(data):
	ip_addr = list()
	for i in data:
		ip_addr.append(str(i))
	ip_addr = ".".join(ip_addr)
	return ip_addr

def parsing_tcp_header(data):
	tcp_header = struct.unpack("!1H1H1I1I1B1B1H1H1H", data)
	src = tcp_header[0]
	dec = tcp_header[1]
	seq = tcp_header[2]
	ack_n = tcp_header[3]
	head_len = int(tcp_header[4]/8)
	flags = tcp_header[5]
	res = int((tcp_header[5]/(2**8))%2)
	nonce = int((tcp_header[5]/(2**7))%2)
	cwr = int((tcp_header[5]/(2**6))%2)
	urgent = int((tcp_header[5]/(2**5))%2)
	ack = int((tcp_header[5]/(2**4))%2)
	push = int((tcp_header[5]/(2**3))%2)
	reset = int((tcp_header[5]/(2**2))%2)
	syn = int((tcp_header[5]/2)%2)
	fin = int(tcp_header[5]%2)
	wsv = tcp_header[6]
	cks = tcp_header[7]
	urg_p = tcp_header[8]
	print("=========tcp_header==========")
	print("src_port: ", src)
	print("dec_port: ", dec)
	print("seq_num: ", seq)
	print("ack_num: ", ack_n)
	print("header_len: ", head_len)
	print("flags: ", flags)
	print(">>>reserved: ", res)
	print(">>>nonce: ", nonce)
	print(">>>cwr: ", cwr)
	print(">>>urgent: ", urgent)
	print(">>>ack: ", ack)
	print(">>>push: ", push)
	print(">>>reset: ", reset)
	print(">>>syn: ", syn)
	print(">>>fin: ", fin)
	print("window_size_value: ", wsv)
	print("checksum: ", cks)
	print("urgent_pointer: ", urg_p)

def parsing_udp_header(data):
	udp_header = struct.unpack("!1H1H1H1H", data)
	src = udp_header[0]
	dst = udp_header[1]
	leng = udp_header[2]
	h_c = hex(udp_header[3])
	print("=========udp_header=========")
	print("src_port: ", src)
	print("dst_port: ", dst)
	print("leng: ", leng)
	print("header checksum: ", h_c)

recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x800))
while True:
	print("<<<<<<Packet Capture Start>>>>>>")
	data = recv_socket.recvfrom(20000)
	parsing_ethernet_header(data[0][0:14])
	if parsing_IP_header(data[0][14:34]) == 6:
		parsing_tcp_header(data[0][34:54])
	else:
		parsing_udp_header(data[0][34:42])
