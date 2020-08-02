#include "pch.h"
#include "PcapAnalysis.h"

bool debug_g = true;
int count_g = 0;
int socks_status_g = SocksUnestablished;
bool flag_certificate_g = false;
const int certificate_buff_size_g = 10000;
u_char certificate_buff[certificate_buff_size_g];
int certificate_buff_len_g = 0;
int focus_src_ip_g, focus_dst_ip_g ;
int focus_src_port_g, focus_dst_port_g;
int src_ip_g, dst_ip_g;
int src_port_g, dst_port_g;

const pcap_pkthdr*pkt_header_g;
const u_char*pkt_data_g;

void set_focus_flow() {
	focus_src_ip_g = src_ip_g;
	focus_dst_ip_g = dst_ip_g;
	focus_src_port_g = src_port_g;
	focus_dst_port_g = dst_port_g;
}

bool is_consistent_flow() {
	if (focus_src_ip_g == src_ip_g and focus_dst_ip_g == dst_ip_g
		and focus_src_port_g == src_port_g and focus_dst_port_g == dst_port_g) {
		return true;
	}
	return false;
}

bool is_reverse_flow() {
	if (focus_src_ip_g == dst_ip_g and focus_dst_ip_g == src_ip_g
		and focus_src_port_g == dst_port_g and focus_dst_port_g == src_port_g) {
		return true;
	}
	return false;
}

void iphdr_ntoh(iphdr_t * iph_host_copy_p, iphdr_t iph) {
	*iph_host_copy_p = iph;
	iph_host_copy_p->tot_len = ntohs(iph.tot_len);
	iph_host_copy_p->id = ntohs(iph.id);
	iph_host_copy_p->flag_off = ntohs(iph.flag_off);
	iph_host_copy_p->check = ntohs(iph.check);
	iph_host_copy_p->saddr = ntohl(iph.saddr);
	iph_host_copy_p->daddr = ntohl(iph.daddr);
}

void udphdr_ntoh(udphdr_t *udph_host_copy_p, udphdr_t udph) {
	*udph_host_copy_p = udph;
	udph_host_copy_p->source = ntohs(udph.source);
	udph_host_copy_p->dest = ntohs(udph.dest);
	udph_host_copy_p->check = ntohs(udph.check);
	udph_host_copy_p->len = ntohs(udph.len);
}

void tcphdr_ntoh(tcphdr_t *tcph_host_copy_p, tcphdr_t tcph) {
	*tcph_host_copy_p = tcph;
	tcph_host_copy_p->source = ntohs(tcph.source);
	tcph_host_copy_p->dest = ntohs(tcph.dest);
	tcph_host_copy_p->seq = ntohl(tcph.seq);
	tcph_host_copy_p->ack_seq = ntohl(tcph.ack_seq);
	tcph_host_copy_p->doff_flags = ntohs(tcph.doff_flags);
	tcph_host_copy_p->window = ntohs(tcph.window);
	tcph_host_copy_p->check = ntohs(tcph.check);
	tcph_host_copy_p->urg_ptr = ntohs(tcph.urg_ptr);
}

bool is_focused_connection(iphdr_t *iph_p, const char* ipaddr1, u_int16_t port1, const char* ipaddr2, u_int16_t port2) {
	iphdr_t iph_host_copy;
	iphdr_ntoh(&iph_host_copy, *iph_p);

	u_int16_t src_port;
	u_int16_t dest_port;
	if (iph_host_copy.protocol == 0x11) {
		udphdr_t* udph_p = (udphdr_t *)((u_char*)iph_p + iph_host_copy.ihl * 4);
		udphdr_t udph_h;
		/* 将网络字节序列转换成主机字节序列 */
		udphdr_ntoh(&udph_h, *udph_p);
		src_port = udph_h.source;
		dest_port = udph_h.dest;
	}
	else if (iph_host_copy.protocol == 0x06)
	{
		tcphdr* tcph_p = (tcphdr_t *)((u_char*)iph_p + iph_host_copy.ihl * 4);
		tcphdr tcph_h;
		tcphdr_ntoh(&tcph_h, *tcph_p);
		src_port = tcph_h.source;
		dest_port = tcph_h.dest;
	}

	char saddr[100], daddr[100];
	ipaddr2string(saddr, 100, iph_host_copy.saddr);
	ipaddr2string(daddr, 100, iph_host_copy.daddr);
	if ((!strcmp(saddr, ipaddr1) and src_port == port1 and !strcmp(daddr, ipaddr2) and dest_port == port2)
		or (!strcmp(daddr, ipaddr1) and dest_port == port1 and !strcmp(saddr, ipaddr2) and src_port == port2)
		)
		return true;
	return false;
}

void ipaddr2string(char* buff, size_t size_of_buff, u_int32_t ipaddr) {
	sprintf_s(buff, size_of_buff, "%d.%d.%d.%d",
		ipaddr >> 24 & 0xff,
		ipaddr >> 16 & 0xff,
		ipaddr >> 8 & 0xff,
		ipaddr & 0xff
	);
}

void show_ipaddr_port(iphdr_t iph_host_copy, u_int16_t src_port, u_int16_t dest_port) {
	char src_addr[100], dest_addr[100];
	ipaddr2string(src_addr, 100, iph_host_copy.saddr);
	ipaddr2string(dest_addr, 100, iph_host_copy.daddr);
	printf_s("%s:%5d\t->\t%s:%5d", src_addr, src_port, dest_addr, dest_port);
}
/* 回调函数原型 */

void show_time() {
	/* 将时间戳转换成可识别的格式 */
	struct tm ltime;
	char timestr[16];
	time_t tv_sec;

	tv_sec = pkt_header_g->ts.tv_sec;
	localtime_s(&ltime, &tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	/* 打印数据包的时间戳和长度 */
	printf_s("%4d | %s.%06d | len=%4d | caplen=%4d |", count_g, timestr, pkt_header_g->ts.tv_usec, pkt_header_g->len, pkt_header_g->caplen);

}

void packet_handler(u_char *param, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	count_g++;//id
	pkt_header_g = pkt_header;
	pkt_data_g = pkt_data;
	

	show_time();

	int ip_header_len;//分析到数据流的第几个字节，表明开始分析的位置

/* 获得IP数据包头部的位置 */
	const u_char* ip_header_data = NULL;

	if (pkt_data[0] == 02 && pkt_data[1] == 00 && pkt_data[2] == 00 && pkt_data[3] == 00) {
		ip_header_len = 4;//Loopback
	}
	else {
		ip_header_len = sizeof(ether_header_t);//Ethernet
	}
	ip_header_data = pkt_data + ip_header_len;
	ip_analysis(ip_header_data, pkt_header->caplen - ip_header_len, pkt_header->caplen);
}

void ip_analysis(const u_char*ip_header_data, int data_len, int caplen) {
	iphdr_t *iph_p = (iphdr_t*)ip_header_data;
	iphdr_t iph_host_copy;
	iphdr_ntoh(&iph_host_copy, *iph_p);

	src_ip_g = iph_host_copy.saddr;
	dst_ip_g = iph_host_copy.daddr;

	/*if (debug) {
		if (!is_focused_connection(iph_p, "192.168.137.44", 53255, "43.243.234.240", 443)) {
			return;
		}
	*/

	/* 获得L4首部的位置 */
	switch (iph_host_copy.protocol)
	{
	case 0x11:
	{const u_char*udp_head_data = ip_header_data + iph_host_copy.ihl * 4;
	udp_analysis(udp_head_data, data_len - iph_p->ihl * 4, iph_host_copy);
	break; }
	case 0x06: {
		const u_char*tcp_head_data = ip_header_data + iph_host_copy.ihl * 4;
		tcp_analysis(tcp_head_data, data_len - iph_p->ihl * 4, iph_host_copy);
		break; }
	default:
		printf("Other Layer 4 Protocol |\n");
		break;
	}
}

void udp_analysis(const u_char* udp_head_data, int data_len, iphdr_t iph_host_copy) {
	udphdr_t *udph_p = (udphdr_t *)udp_head_data;
	udphdr_t udph_host_copy;
	/* 将网络字节序列转换成主机字节序列 */
	udphdr_ntoh(&udph_host_copy, *udph_p);

	/* 打印IP地址和端口 */
	printf_s("UDP | ");
	show_ipaddr_port(iph_host_copy, udph_host_copy.source, udph_host_copy.dest);
	printf_s("\n");
}

void tcp_analysis(const u_char* tcp_head_data, int data_len, iphdr_t iph_host_copy) {
	tcphdr_t *tcph_p = (tcphdr_t *)tcp_head_data;
	tcphdr tcph_host_copy;
	tcphdr_ntoh(&tcph_host_copy, *tcph_p);

	src_port_g = tcph_host_copy.source;
	dst_port_g = tcph_host_copy.dest;

	printf_s("TCP | ");
	show_ipaddr_port(iph_host_copy, tcph_host_copy.source, tcph_host_copy.dest);
	printf_s("\n");
	
	//是否只是一个四层协议，没有tcp payload
	if (get_tcp_len(tcph_p) >= data_len) {
		return;
	}
	
	data_len -= get_tcp_len(tcph_p);

	const u_char* tcp_payload = tcp_head_data + get_tcp_len(tcph_p);
	if (!flag_certificate_g) {
		tcp_payload_analysis(tcp_payload, data_len);
	}
	else {
		if (is_consistent_flow()) {
			memcpy_s(certificate_buff + certificate_buff_len_g, certificate_buff_size_g - certificate_buff_len_g,
				tcp_payload, data_len);
			certificate_buff_len_g = certificate_buff_len_g + data_len;
		}
		else if(is_reverse_flow())
		{
			printf_tab(1);
			printf("---- Last Flow Start ----\n");
			tls_analysis(certificate_buff, certificate_buff_len_g);
			printf_tab(1);
			printf("---- Last Flow End ----\n");
			certificate_buff_len_g = 0;
			flag_certificate_g = false;
			tcp_payload_analysis(tcp_payload,data_len);
		}
		else
		{
			tcp_payload_analysis(tcp_payload, data_len);
		}
	}
}

void tcp_payload_analysis(const u_char*tcp_payload, int data_len) {
	u_int8_t magic_number = *tcp_payload;
	switch (magic_number)
	{
	case 0x05://socket version 5
		socks_analysis(tcp_payload, data_len );
		break;
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
		tls_analysis(tcp_payload, data_len );
		break;
	default:
		break;
	}
}

void socks_analysis(const u_char*socks_data, int data_len) {
	printf_tab(1);
	int offset = 0;
	if (socks_status_g == SocksCommandResponse)
	{
		socks_status_g = SocksConnectToServerRequest;
	}
	else {
		socks_status_g++;//前两次建立连接，后两次命令交互
	}
	switch (socks_status_g)
	{
	case SocksConnectToServerRequest:
		printf("- Socks: Version 5\n\t- Connect To Server Request\n");
		break;
	case SocksConnectToServerResponse:
		printf("- Socks: Version 5\n\t- Connect To Server Response\n");
		break;
	case SocksCommandRequest:
		printf("- Socks: Version 5\n\t- Command Request\n");
		offset += 1;//command
		if (*(socks_data + offset) == 0x01) {//Command: Connect
			printf_tab(2);
			printf_s("- Connect\n");

			offset += 1;//reserved

			offset += 1;//address type
			if (*(socks_data + offset) == 0x03) {//domian name
				offset += 1;//Remote name
				const int buff_size = 200;
				char domain_name[buff_size + 1];
				int domain_name_len = data_len - offset - 2;
				strncpy_s(domain_name, buff_size, (char*)(socks_data + offset), domain_name_len);
				domain_name[min(domain_name_len, buff_size)] = 0;
				trim(domain_name);

				offset = data_len - 2;//port
				int port = ntohs(*(u_int16_t*)(socks_data + data_len - 2));
				printf_tab(3);
				printf_s("- Domain Name: %s\n", domain_name);

				printf_tab(3);
				printf_s("- Port: %d\n", port);
				offset = data_len;//next
			}
		}
		break;
	case SocksCommandResponse:

		printf_s("- Socks: Version 5\n\t- Command Response\n");
		offset += 1;
		if (*(socks_data + offset) == 0x00) {
			printf_tab(2);
			printf("- Succeed\n");

			offset += 1;//reserved

			offset += 1;//address type
			if (*(socks_data + offset) == 0x01) {
				printf_tab(3);
				printf("- Address Type: IPv4\n");
			}
			offset += 1;//remote addr
			char remote_addr[100];
			ipaddr2string(remote_addr, 100, ntohl(*((u_int32_t*)(socks_data + offset))));

			offset += 4;//port
			int port = ntohs(*(u_int16_t*)(socks_data + data_len - 2));
			printf_tab(3);
			printf_s("- Remote Address: %s\n", remote_addr);

			printf_tab(3);
			printf_s("- Port: %d\n", port);
			offset += 2;//next
		}
		break;
	default:
		break;
	}
}

void tls_analysis(const u_char * tls_data, int data_len) {
	
	if (data_len <= 0) {
		return;
	}
	printf_tab(1);
	u_int8_t tls_content_type = *tls_data;
	int offset = 0;

	switch (tls_content_type)
	{
	case 0x14://Change Cipher Spec


		offset += 1;//version
		if (*(tls_data + offset) == 0x03 and *(tls_data + offset + 1) == 0x03) {
			printf("- TLS 1.2: Change Cipher Spec\n");

			offset += 2;//length
			u_int16_t length = ntohs(*(u_int16_t*)(tls_data + offset));

			offset += 2;//content

			offset += 1;//next
		}
		break;
	case 0x15://Alert
		printf("- TLS 1.2: Alert\n");
		return;
	case 0x16://Handshake

		offset += 1;//version
		if (*(tls_data + offset) == 0x03 and *(tls_data + offset + 1) == 0x03) {//tls 1.2
			printf("- TLS 1.2: Handshake\n");

			offset += 2;//length
			u_int16_t length = ntohs(*(u_int16_t*)(tls_data + offset));

			offset += 2;//handshake protocol
			const u_char* tls_handshake_protocol_data = tls_data + offset;

			tls_handshake_protocol_data_analysis(tls_handshake_protocol_data);
			
			offset += length;//next
		}
		else if(*(tls_data + offset) == 0x03 and *(tls_data + offset + 1) == 0x01)//tls1.0
		{
			printf("- TLS 1.0: Handshake\n");

			offset += 2;//length
			u_int16_t length = ntohs(*(u_int16_t*)(tls_data + offset));

			offset += 2;//handshake protocol
			const u_char* tls_handshake_protocol_data = tls_data + offset;


			tls_handshake_protocol_data_analysis_1_0(tls_handshake_protocol_data);
			
			offset += length;//next
		}
		break;
	case 0x17://Applicaiton
		printf("- TLS 1.2: Applicaiton\n");
		offset += 1;//version
		if (*(tls_data + offset) == 0x03 and *(tls_data + offset + 1) == 0x03) {
			offset += 2;//length
			u_int16_t length = ntohs(*(u_int16_t*)(tls_data + offset));
			offset += 2;//encrypted app data

			offset += length;//next
			break;
		}
		else
		{
			return;
		}

	default:
		return;
	}

	data_len -= offset;
	if (flag_certificate_g) {
		memcpy_s(certificate_buff, certificate_buff_size_g, tls_data + offset, data_len);
		certificate_buff_len_g += data_len;
	}
	else
	{
		tls_analysis(tls_data + offset, data_len);
	}

}

void tls_handshake_protocol_data_analysis(const u_char*tls_handshake_protocol_data) {
	printf_tab(2);

	u_int8_t handshake_type = *tls_handshake_protocol_data;
	int offset = 0;
	switch (handshake_type) {
	case 0x01: {
		printf("- Handshake Type: Client Hello\n");

		offset += 1;//length
		int length = ntoh_3byte(tls_handshake_protocol_data, offset);

		offset += 3;//Version

		offset += 2;//Random

		offset += 32;//Session ID Length
		u_int8_t session_id_length = tls_handshake_protocol_data[offset];

		offset += 1;//Session ID

		offset += session_id_length;//Cipher Suties Length
		u_int16_t cipher_suties_length = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));

		offset += 2;//Cipher Suites
		const int buff_size = 200;
		char cipher_suite[buff_size + 1];
		
		for (int i = 0; i < cipher_suties_length / 2; i++, offset += 2) {
			u_int16_t cipher_suite_index = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));
			get_cipher_suite(cipher_suite, buff_size, cipher_suite_index);
			printf_tab(3);
			printf_s("- %s\n", cipher_suite);
		}


		//offset += cipher_suties_length;//Compression Methods Length
		u_int8_t compression_methods_length = tls_handshake_protocol_data[offset];

		offset += 1;//Compression Methods

		offset += compression_methods_length;//Extension Length
		u_int16_t extension_length = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));

		offset += 2;//Extension

		const u_char* tls_handshake_extension_data = tls_handshake_protocol_data + offset;

		tls__handshake_extension_data_analysis(tls_handshake_extension_data, extension_length);

		break;
	}
	case 0x02: {
		printf("- Handshake Type: Server Hello\n");
		flag_certificate_g = true;
		set_focus_flow();
	

		offset += 1;//length
		int length = ntoh_3byte(tls_handshake_protocol_data, offset);

		offset += 3;//Version

		offset += 2;//Random

		offset += 32;//Session ID Length
		u_int8_t session_id_length = tls_handshake_protocol_data[offset];

		offset += 1;//Session ID

		offset += session_id_length;//Cipher Suties
		u_int16_t cipher_suite_index = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));
		const int buff_size = 200;
		char cipher_suite[buff_size + 1];
		
		get_cipher_suite(cipher_suite, buff_size, cipher_suite_index);
		printf_tab(3);
		printf_s("- %s\n", cipher_suite);

		offset += 2;//Compression Methods

		offset += 1;//Extension Length
		u_int16_t extension_length = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));

		offset += 2;//Extension

		const u_char* tls_handshake_extension_data = tls_handshake_protocol_data + offset;

		tls__handshake_extension_data_analysis(tls_handshake_extension_data, extension_length);

		break;
	}
	case 0x10: {
		printf("- Handshake Type: Client Key Exchange\n");
		break;
	}
	case 0x16: {
		printf("- Handshake Type: Encrypted Handshake Message\n");
		break;
	}
	case 0x04: {
		printf("- Handshake Type: New Session Ticket\n");
		break;
	}
	case 0x0b: {
		printf("- Handshake Type: Certificate\n");

		offset += 1;//length
		int length = ntoh_3byte(tls_handshake_protocol_data, offset);

		offset += 3;//certificates length
		int certificates_length = ntoh_3byte(tls_handshake_protocol_data, offset);

		offset += 3;//certificates
		const u_char* certificates_data = tls_handshake_protocol_data + offset;
		
		certificates_data_analysis(certificates_data, certificates_length);
		break;
	}
	case 0x0c: {
		printf("- Handshake Type: Server Key Exchange\n");
		break;
	}
	case 0x0e: {
		printf("- Handshake Type: Server Hello Done\n");
		break;
	}
	default:
		printf("- Handshake Type: Encrypted Handshake Message\n");
		break;
	}
}

void tls_handshake_protocol_data_analysis_1_0(const u_char*tls_handshake_protocol_data) {
	printf_tab(2);

	u_int8_t handshake_type = *tls_handshake_protocol_data;
	int offset = 0;
	switch (handshake_type) {
	case 0x01: {
		printf("- Handshake Type: Client Hello\n");

		offset += 1;//length
		int length = ntoh_3byte(tls_handshake_protocol_data, offset);

		offset += 3;//Version
		if (*(tls_handshake_protocol_data + offset) == 0x03 and *(tls_handshake_protocol_data + offset + 1) == 0x03) {
			offset += 2;//Random

			offset += 32;//Session ID Length
			u_int8_t session_id_length = tls_handshake_protocol_data[offset];

			offset += 1;//Session ID

			offset += session_id_length;//Cipher Suties Length
			u_int16_t cipher_suties_length = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));

			offset += 2;//Cipher Suites
			const int buff_size = 200;
			char cipher_suite[buff_size + 1];
			for (int i = 0; i < cipher_suties_length / 2; i++, offset += 2) {
				u_int16_t cipher_suite_index = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));
				get_cipher_suite(cipher_suite, buff_size, cipher_suite_index);
				printf_tab(3);
				printf_s("- %s\n", cipher_suite);
			}


			//offset += cipher_suties_length;//Compression Methods Length
			u_int8_t compression_methods_length = tls_handshake_protocol_data[offset];

			offset += 1;//Compression Methods

			offset += compression_methods_length;//Extension Length
			u_int16_t extension_length = ntohs(*(u_int16_t*)(tls_handshake_protocol_data + offset));

			offset += 2;//Extension

			const u_char* tls_handshake_extension_data = tls_handshake_protocol_data + offset;

			tls__handshake_extension_data_analysis(tls_handshake_extension_data, extension_length);
		}
		
		break;
	}
	
	default:
		break;
	}
}

int ntoh_3byte(const u_char*data, int offset) {
	return ((int)data[offset] & 0xff) *pow(2, 16)
		+ ((int)(data[offset + 1]) & 0xff) *pow(2, 8)
		+ ((int)data[offset + 2] & 0xff);
}

void certificates_data_analysis(const u_char* certificates_data, int data_len) {
	if (data_len <= 0) {
		return;
	}
	printf_tab(3);
	printf("- Certificates\n");
	int offset = 0;
	int certificate_length = ntoh_3byte(certificates_data, offset);

	offset += 3;//certificate
	const u_char* certificate_data = certificates_data + offset;
	
	certificate_data_analysis(certificate_data, certificate_length);

	offset += certificate_length;//next
	data_len -= offset;
	if (count_g == 139) {
		printf_tab(1);
	}
	certificates_data_analysis(certificates_data + offset, data_len);
}

void printf_tab(int n) {
	printf("    ");
	for (int i = 0; i < n - 1; i++) {
		printf("- - ");
	}
}

void certificate_data_analysis(const u_char* certificate_data, int data_len) {
	printf_tab(4);
	printf_s("- Certificate:\n");
	int offset = 0;//reserved

	offset += 4;//signed certificate

	offset += 8;//version

	offset += 1;//reserved

	offset += 1;//serial number len
	u_int8_t serial_number_len = *(certificate_data + offset);

	offset += 1;//serialnumber

	offset += serial_number_len;//signature

	offset += 3;//signature len
	u_int8_t sig_len = *(certificate_data + offset);

	offset += 1;//sign

	offset += sig_len;//reserved

	offset += 2;//issuer

	offset += 1;// rdn seq length
	u_int8_t issure_rdn_seq_len = *(certificate_data + offset);

	offset += 1;//rdn seq
	const u_char*issure_rdn_seq = certificate_data + offset;
	printf_tab(5);
	printf("- Issuer:\n");
	rdn_seq_analysis(issure_rdn_seq, issure_rdn_seq_len);

	offset += issure_rdn_seq_len;//validity

	offset += 1;//validity len
	u_int8_t validity_len = *(certificate_data + offset);

	offset += 1;//validity not before

	offset += 1;//not before len
	u_int8_t not_before_len = *(certificate_data + offset);

	offset += 1;//not before
	const u_char*c = certificate_data + offset;
	printf_tab(5);
	printf_s("- Not Before: %c%c-%c%c-%c%c %c%c:%c%c:%c%c\n", *c, *(c + 1), *(c + 2), *(c + 3), *(c + 4), *(c + 5), *(c + 6), *(c + 7), *(c + 8), *(c + 9), *(c + 10), *(c + 11));

	offset += not_before_len;//validity not after

	offset += 1;//not after len
	u_int8_t not_after_len = *(certificate_data + offset);

	offset += 1;//not after
	c = certificate_data + offset;
	printf_tab(5);
	printf_s("- Not After: %c%c-%c%c-%c%c %c%c:%c%c:%c%c\n", *c, *(c + 1), *(c + 2), *(c + 3), *(c + 4), *(c + 5), *(c + 6), *(c + 7), *(c + 8), *(c + 9), *(c + 10), *(c + 11));

	offset += not_after_len;//subject

	while (true) {
		offset += 1;
		u_int8_t flag = *(certificate_data + offset);
		if (flag == 0x31) {//rdn seq
			break;
		}
	}
	u_int8_t subject_rdn_seq_len = *(certificate_data + offset-1);//len


	const u_char*subject_rdn_seq = certificate_data + offset;//rdn seq
	printf_tab(5);
	printf("- Subject:\n");
	
	rdn_seq_analysis(subject_rdn_seq, subject_rdn_seq_len);

	offset += subject_rdn_seq_len;//subject pubkey info

}


void rdn_seq_analysis(const u_char*rdn_seq_data, int data_len) {
	if (data_len <= 0) {
		return;
	}
	printf_tab(6);
	int offset = 0;

	offset += 1;//rdn seq item len
	u_int8_t rdn_seq_item_len = *(rdn_seq_data + offset);

	offset += 1;//rdn seq item

	offset += 3;//id len
	u_int8_t id_len = *(rdn_seq_data + offset);

	offset += 1;//id

	offset += id_len;//reserved

	offset += 1;//directory str len
	u_int8_t directory_str_len = *(rdn_seq_data + offset);

	offset += 1;//directory str
	const int buff_size = 200;
	char  directory_str[buff_size + 1];
	strncpy_s(directory_str, buff_size, (char*)(rdn_seq_data + offset), directory_str_len);
	directory_str[min(buff_size, directory_str_len)] = 0;

	printf_s("- %s\n", directory_str);

	offset += directory_str_len;//next

	data_len -= offset;

	rdn_seq_analysis(rdn_seq_data + offset, data_len);
}

void get_cipher_suite(char* cipher_suite, int buff_size, int index) {
	memset(cipher_suite, 0, buff_size + 1);
	switch (index)
	{
	case 0xc02f:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)");
		break;
	case 0xc02c:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c)");
		break;
	case 0xc02b:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b)");
		break;
	case 0xc030:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)");
		break;
	case 0xc024:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)");
		break;
	case 0xc023:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)");
		break;
	case 0xc028:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)");
		break;
	case 0xc027:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)");
		break;
	case 0xc00a:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)");
		break;
	case 0xc009:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)");
		break;
	case 0xc014:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)");
		break;
	case 0xc013:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)");
		break;
	case 0x009d:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)");
		break;
	case 0x009c:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)");
		break;
	case 0x003d:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)");
		break;
	case 0x003c:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)");
		break;
	case 0x0035:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)");
		break;
	case 0x002f:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)");
		break;
	case 0x000a:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)");
		break;
	default:
		strcpy_s(cipher_suite, buff_size, "Cipher Suite: Other");
		break;
	}
}

void tls__handshake_extension_data_analysis(const u_char* tls__handshake_extension_data, int data_len) {
	if (data_len <= 0) {
		return;
	}
	printf_tab(3);
	u_int16_t type = ntohs(*(u_int16_t*)tls__handshake_extension_data);
	int offset = 0;
	switch (type)
	{
	case 0x00://server name
	{
		printf_s("- Server Name Extension\n");
		offset += 2;//length
		u_int16_t length = ntohs(*(u_int16_t*)(tls__handshake_extension_data + offset));

		offset += 2;//server name indication extension

		const u_char*server_name_indication_extension_data = tls__handshake_extension_data + offset;
		server_name_indication_extension_analysis(server_name_indication_extension_data);
		offset += length;
		break;
	}
	default:
		printf_s("- Other Extension\n");
		return;
	}
	data_len -= offset;



	tls__handshake_extension_data_analysis(tls__handshake_extension_data + offset, data_len);

}

void server_name_indication_extension_analysis(const u_char*server_name_indication_extension_data) {
	printf_tab(4);

	int offset = 0;
	u_int16_t server_name_list_length = ntohs(*(u_int16_t*)(server_name_indication_extension_data + offset));

	offset += 2;//server name list data
	const u_char*server_name_list_data = server_name_indication_extension_data + offset;
	printf_s("- Server Name List:\n");
	server_name_list_analysis_tls(server_name_list_data, server_name_list_length);


}

void server_name_list_analysis_tls(const u_char*server_name_list_data, int data_len) {

	if (data_len <= 0) {
		return;
	}
	printf_tab(5);
	int offset = 0;
	u_int8_t server_name_type = server_name_list_data[offset];
	switch (server_name_type)
	{
	case 0x00://host name
	{
		offset += 1;//server name length
		u_int16_t server_name_length = ntohs(*(u_int16_t*)(server_name_list_data + offset));

		offset += 2;//server name
		const int buff_size = 200;
		char server_name[buff_size + 1];
		strncpy_s(server_name, buff_size, (char*)(server_name_list_data + offset), server_name_length);
		server_name[min(buff_size, server_name_length)] = 0;
		printf_s("- Host Name: %s\n", server_name);
		offset += server_name_length;
		break;
	}
	default:
		printf_s("- Other Server Name Type\n");
		return;
	}
	data_len -= offset;
	server_name_list_analysis_tls(server_name_list_data + offset, data_len);
}

int get_tcp_len(tcphdr_t* tcph_p) {
	return (tcph_p->doff_flags >> 4 & 0xf) * 4;
}

void trim_left(char*str) {
	for (int i = 0; i < strlen(str); i++) {
		if (str[i] < 32) {
			str[i] = 46;
		}
		else
		{
			break;
		}
	}
}

void trim_right(char*str) {
	int str_len = strlen(str);
	for (int i = str_len - 1; i >= 0; i--) {
		if (str[i] < 32) {
			str[i] = 46;
		}
		else
		{
			break;
		}
	}
	str[str_len] = 0;
}

void trim(char*str) {
	trim_left(str);
	trim_right(str);
}

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	//char filename[100] = "youtube.pcap";
	char filename[100] = "facetime.pcap";
	//输入要读取的pcap文件
	if (argc == 2)
	{
		strcpy_s(filename, sizeof(argv[1]), argv[1]);
	}

	//打开pcap文件
	if ((fp = pcap_open_offline(filename, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open: %s.\n", filename);
		return -1;
	}
	const int filter_str_size = 1000;
	char filter_str[filter_str_size] = {0};
	if (debug_g) {
		//strcpy_s(filter_str, filter_str_size, "(src host 127.0.0.1 and src port 59878 and dst host 127.0.0.1 and dst port 56568) or (src host 127.0.0.1 and src port 56568 and dst host 127.0.0.1 and dst port 59878)");
		//strcpy_s(filter_str, filter_str_size, "(src host 192.168.137.44 and dst host 43.243.234.240 ) or (src host 43.243.234.240  and dst host 192.168.137.44 )");

	}
	else
	{
		printf("Filter: ");
		scanf_s("%[^\n]", filter_str, filter_str_size);
	}
	
	if (strlen(filter_str)) {
		struct bpf_program filter;
		if (pcap_compile(fp, &filter,
			filter_str,
			1, 0) < 0
			)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			/* 释放 */
			pcap_close(fp);
			return -1;
		}

		if (pcap_setfilter(fp, &filter) < 0)
		{
			fprintf(stderr, "\nError setting the filter.\n");
			/* 释放 */
			pcap_close(fp);
			return -1;
		}
	}
	
	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, packet_handler, NULL);

	//关闭打开pcap文件的指针
	pcap_close(fp);
	return 0;
}