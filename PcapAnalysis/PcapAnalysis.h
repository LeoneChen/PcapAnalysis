#pragma once
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#pragma comment (lib,"Ws2_32.lib") 

#define SocksUnestablished 0
#define SocksConnectToServerRequest 1
#define SocksConnectToServerResponse 2
#define SocksCommandRequest 3
#define SocksCommandResponse 4


/*Ethernet �ײ�*/
constexpr auto ETH_ALEN = 6;
typedef struct  ether_header
{
	u_int8_t ether_dhost[ETH_ALEN];   //Ŀ��MAC��ַ
	u_int8_t ether_shost[ETH_ALEN];   //ԴMAC��ַ
	u_int16_t  ether_type;               //֡����
}ether_header_t;

/*IP �ײ�*/

typedef struct iphdr
{
	u_int8_t ihl : 4;	//�ײ�����
	u_int8_t version : 4;//�汾
	u_int8_t tos;			// ��������
	u_int16_t tot_len;		// �ܳ���
	u_int16_t id;			// ��ʶ
	u_int16_t flag_off;     // ��־��Ƭƫ��
	u_int8_t ttl;           // ����ʱ��
	u_int8_t protocol;      // Э��
	u_int16_t check;        // �ײ�У���
	u_int32_t saddr;        // Դ��ַ
	u_int32_t daddr;        // Ŀ�ĵ�ַ
	/*The options start here. */
}iphdr_t;

/* UDP �ײ�*/
typedef struct udphdr
{
	u_int16_t source;         // Դ�˿ں�
	u_int16_t dest;             // Ŀ�Ķ˿ں�
	u_int16_t len;               // ����
	u_int16_t check;          // У���
}udphdr_t;

/*TCP �ײ�*/
typedef struct tcphdr
{
	u_int16_t source;			// Դ�˿ں�
	u_int16_t dest;				// Ŀ�Ķ˿ں�
	u_int32_t seq;				// ���к�
	u_int32_t ack_seq;			// ȷ������
	u_int16_t doff_flags;		//�ײ����Ⱥͱ�־λ
	u_int16_t window;			// ����  
	u_int16_t check;			//У���
	u_int16_t urg_ptr;			//����ָ��
}tcphdr_t;



void iphdr_ntoh(iphdr_t * iph_host_copy_p, iphdr_t iph);
void udphdr_ntoh(udphdr_t *udph_host_copy_p, udphdr_t udph);
void tcphdr_ntoh(tcphdr_t *tcph_host_copy_p, tcphdr_t tcph);
void ipaddr2string(char* buff,size_t size_of_buff, u_int32_t ipaddr);
void show_ipaddr_port(iphdr_t iph_host_copy, u_int16_t src_port, u_int16_t dest_port);
bool is_focused_connection(iphdr_t *iph_p, const char* ipaddr1, u_int16_t port1, const char* ipaddr2, u_int16_t port2);
int get_tcp_len(tcphdr_t* tcph_p);
void trim_left(char*str);
void trim_right(char*str);
void trim(char*str);
void packet_handler(u_char *param, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void ip_analysis(const u_char*ip_header_data, int data_len, int caplen);
void udp_analysis(const u_char* udp_head_data, int data_len, iphdr_t iph_host_copy);
void tcp_analysis(const u_char* tcp_head_data, int data_len, iphdr_t iph_host_copy);
void socks_analysis(const u_char*socks_data, int data_len);
void tls_analysis(const u_char * tls_data, int data_len);
void tls_handshake_protocol_data_analysis(const u_char*tls_handshake_protocol_data);
void tls__handshake_extension_data_analysis(const u_char* tls__handshake_extension_data, int data_len);
void server_name_indication_extension_analysis(const u_char*server_name_indication_extension_data);
void server_name_list_analysis_tls(const u_char*server_name_list_data, int data_len);
void get_cipher_suite(char* cipher_suite, int buff_size, int index);
void rdn_seq_analysis(const u_char*rdn_seq_data, int data_len);
void certificate_data_analysis(const u_char* certificate_data, int data_len);
int ntoh_3byte(const u_char*data, int offset);
void certificates_data_analysis(const u_char* certificates_data, int data_len);
void printf_tab(int n);
void tls_handshake_protocol_data_analysis_1_0(const u_char*tls_handshake_protocol_data);
void tcp_payload_analysis(const u_char*tcp_payload, int data_len);