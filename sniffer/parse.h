#pragma once
#include"framework.h"
#include"packetque.h"
#define PROTO_ARP 0x0806
#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x86dd
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17



//Mac帧头 占14个字节
typedef struct eth_header
{
	u_char dest[6];			//6个字节 目标地址
	u_char src[6];			//6个字节 源地址
	u_short type;			//2个字节 类型
}eth_header;

//ARP头
typedef struct arp_header
{
	u_short hrd;				//硬件类型
	u_short protocol;			//协议类型
	u_char hrdlen;				//硬件地址长度
	u_char prolen;				//协议地址长度
	u_short opcode;				//操作码
	u_char srcmac[6];			//发送方MAC
	u_char srcip[4];			//发送方IP
	u_char destmac[6];			//接收方MAC
	u_char destip[4];			//接收方IP
}arp_header;

//定义IPv4头
typedef struct ipv4_header
{
	u_char headerlen : 4;			//首部长度
	u_char version : 4;				//版本 
	u_char tos;						//TOS 服务类型
	u_short totallen;				//包总长 
	u_short flag;					//标识
	u_short fragoffset;				//片位移
	u_char ttl;						//生存时间
	u_char protocol;				//协议
	u_short checksum;				//校验和
	u_int srcip;					//源地址
	u_int destip;					//目的地址
	void*	option;					//可选项,如需使用需要自行另外malloc
}ipv4_header;

//定义IPv6
typedef struct ipv6_header
{
	u_int version : 4;			//版本
	u_int flowtype : 8;			//流类型
	u_int flowid : 20;			//流标签
	u_short payloadlen;			//有效载荷长度
	u_char nexthead;			//下一个头部
	u_char hoplimit;			//跳限制
	u_short srcaddr[8];			//源地址
	u_short destaddr[8];		//目的地址
	void* extension;			//可选项,如需使用需要自行另外malloc
}ipv6_header;

//定义TCP头
typedef struct tcp_header
{
	u_short srcport;				//源端口地址  16位
	u_short destport;				//目的端口地址 16位
	u_int seq;						//序列号 32位
	u_int ack;						//确认序列号
	u_char unused : 4;				//保留
	u_char headlen : 4;				//头部长度
	u_char fin : 1;					//标识
	u_char syn : 1;
	u_char rst : 1;
	u_char psh : 1;
	u_char ackbit : 1;
	u_char urg : 1;
	u_char ece : 1;
	u_char cwr : 1;
	u_short winsize;				//窗口大小 16位
	u_short checksum;				//校验和 16位
	u_short urgptr;					//紧急指针 16位
	void* option;					//可选选项
}tcp_header;

//定义UDP头
typedef struct udp_header
{
	u_short srcport;		//源端口  16位
	u_short destport;		//目的端口 16位
	u_short len;			//数据报长度 16位
	u_short checksum;		//校验和 16位
}udp_header;

//定义ICMP
typedef struct icmp_header
{
	u_char type;			//8位 类型
	u_char code;			//8位 代码
	u_char seq;				//序列号 8位
	u_char checksum;		//8位校验和
}icmp_header;

//对各种包进行计数
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

//要保存的数据结构,直接定义好整个结构体虽然会造成一定的空间浪费，但能节省时间，避免频繁malloc
typedef struct parsed_packet
{
	char  pktType[8];				//包类型
	int time[6];					//时间
	int len;						//长度
	eth_header ethh;				//链路层包头
	arp_header arph;				//ARP包头
	ipv4_header ipv4h;				//IPV4包头
	ipv6_header ipv6h;				//IPV6包头
	icmp_header icmph;				//ICMP包头
	udp_header udph;				//UDP包头
	tcp_header tcph;				//TCP包头
	void* apph;						//应用层包头
	u_char* rawdata;				//原始数据指针
}parsed_packet;

//解析主线程函数
DWORD WINAPI Parse(PVOID pParam);

//预处理时间戳、长度、原始数据
void PreAnalyze(packet_t* pkt);

//以太网帧解析函数
BOOL AnalyzeEth(u_char* pkt);

//arp协议解析函数
void AnalyzeArp(u_char* pkt);

//ipv4解析函数
BOOL AnalyzeIpv4(u_char* pkt);

//ipv6解析函数
BOOL AnalyzeIpv6(u_char* pkt);

//icmp解析函数
void AnalyzeIcmp(u_char* pkt);

//tcp解析函数
void AnalyzeTcp(u_char* pkt);

//udp解析函数
void AnzlyzeUdp(u_char* pkt);

//显示包信息
void ShwoPktInfo(HWND hPktInfo);

//显示包数目
void ShowPktCount(HWND hDlg);

//显示选中的数据包信息
void ShowPktDetail(HWND hDlg);

//将字节流数据转换为显示在edit中的格式数据
void FormStream(__in int number, __out LPSTR data);