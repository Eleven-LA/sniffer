#pragma once
#include"framework.h"
#include"packetque.h"
#define PROTO_ARP 0x0806
#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x86dd
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17



//Mac֡ͷ ռ14���ֽ�
typedef struct eth_header
{
	u_char dest[6];			//6���ֽ� Ŀ���ַ
	u_char src[6];			//6���ֽ� Դ��ַ
	u_short type;			//2���ֽ� ����
}eth_header;

//ARPͷ
typedef struct arp_header
{
	u_short hrd;				//Ӳ������
	u_short protocol;			//Э������
	u_char hrdlen;				//Ӳ����ַ����
	u_char prolen;				//Э���ַ����
	u_short opcode;				//������
	u_char srcmac[6];			//���ͷ�MAC
	u_char srcip[4];			//���ͷ�IP
	u_char destmac[6];			//���շ�MAC
	u_char destip[4];			//���շ�IP
}arp_header;

//����IPv4ͷ
typedef struct ipv4_header
{
	u_char headerlen : 4;			//�ײ�����
	u_char version : 4;				//�汾 
	u_char tos;						//TOS ��������
	u_short totallen;				//���ܳ� 
	u_short flag;					//��ʶ
	u_short fragoffset;				//Ƭλ��
	u_char ttl;						//����ʱ��
	u_char protocol;				//Э��
	u_short checksum;				//У���
	u_int srcip;					//Դ��ַ
	u_int destip;					//Ŀ�ĵ�ַ
	void*	option;					//��ѡ��,����ʹ����Ҫ��������malloc
}ipv4_header;

//����IPv6
typedef struct ipv6_header
{
	u_int version : 4;			//�汾
	u_int flowtype : 8;			//������
	u_int flowid : 20;			//����ǩ
	u_short payloadlen;			//��Ч�غɳ���
	u_char nexthead;			//��һ��ͷ��
	u_char hoplimit;			//������
	u_short srcaddr[8];			//Դ��ַ
	u_short destaddr[8];		//Ŀ�ĵ�ַ
	void* extension;			//��ѡ��,����ʹ����Ҫ��������malloc
}ipv6_header;

//����TCPͷ
typedef struct tcp_header
{
	u_short srcport;				//Դ�˿ڵ�ַ  16λ
	u_short destport;				//Ŀ�Ķ˿ڵ�ַ 16λ
	u_int seq;						//���к� 32λ
	u_int ack;						//ȷ�����к�
	u_char unused : 4;				//����
	u_char headlen : 4;				//ͷ������
	u_char fin : 1;					//��ʶ
	u_char syn : 1;
	u_char rst : 1;
	u_char psh : 1;
	u_char ackbit : 1;
	u_char urg : 1;
	u_char ece : 1;
	u_char cwr : 1;
	u_short winsize;				//���ڴ�С 16λ
	u_short checksum;				//У��� 16λ
	u_short urgptr;					//����ָ�� 16λ
	void* option;					//��ѡѡ��
}tcp_header;

//����UDPͷ
typedef struct udp_header
{
	u_short srcport;		//Դ�˿�  16λ
	u_short destport;		//Ŀ�Ķ˿� 16λ
	u_short len;			//���ݱ����� 16λ
	u_short checksum;		//У��� 16λ
}udp_header;

//����ICMP
typedef struct icmp_header
{
	u_char type;			//8λ ����
	u_char code;			//8λ ����
	u_char seq;				//���к� 8λ
	u_char checksum;		//8λУ���
}icmp_header;

//�Ը��ְ����м���
typedef struct pkt_count
{
	int n_ipv4;
	int n_ipv6;
	int n_arp;
	int n_tcp;
	int n_udp;
	int n_icmp;
	int n_http;
	int n_https;
	int n_total;
}pkt_count;

//Ҫ��������ݽṹ,ֱ�Ӷ���������ṹ����Ȼ�����һ���Ŀռ��˷ѣ����ܽ�ʡʱ�䣬����Ƶ��malloc
typedef struct parsed_packet
{
	char  pktType[8];				//������
	int time[6];					//ʱ��
	int len;						//����
	eth_header ethh;				//��·���ͷ
	arp_header arph;				//ARP��ͷ
	ipv4_header ipv4h;				//IPV4��ͷ
	ipv6_header ipv6h;				//IPV6��ͷ
	icmp_header icmph;				//ICMP��ͷ
	udp_header udph;				//UDP��ͷ
	tcp_header tcph;				//TCP��ͷ
	void* apph;						//Ӧ�ò��ͷ
	u_char* rawdata;				//ԭʼ����ָ��
}parsed_packet;

//�������̺߳���
DWORD WINAPI Parse(PVOID pParam);

//Ԥ����ʱ��������ȡ�ԭʼ����
void PreAnalyze(packet_t* pkt);

//��̫��֡��������
BOOL AnalyzeEth(u_char* pkt);

//arpЭ���������
void AnalyzeArp(u_char* pkt);

//ipv4��������
BOOL AnalyzeIpv4(u_char* pkt);

//ipv6��������
BOOL AnalyzeIpv6(u_char* pkt);

//icmp��������
void AnalyzeIcmp(u_char* pkt);

//tcp��������
void AnalyzeTcp(u_char* pkt);

//udp��������
void AnzlyzeUdp(u_char* pkt);

//��ʾ����Ϣ
void ShwoPktInfo(HWND hPktInfo);

//��ʾ����Ŀ
void ShowPktCount(HWND hDlg);

//��ʾѡ�е����ݰ���Ϣ
void ShowPktDetail(HWND hDlg);

//���ֽ�������ת��Ϊ��ʾ��edit�еĸ�ʽ����
void FormStream(__in int number, __out LPSTR data);