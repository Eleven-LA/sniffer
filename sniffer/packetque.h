#pragma once
#include"framework.h"

//队列中的数据包结构
typedef struct packet {
	pcap_pkthdr* header;//指向基础包数据
	u_char* pkt_data;//指向包数据
	packet* packet_next;//指向下一个数据包结构
}packet_t;

//初始化数据包队列
void PacketQueueInit();

//包入队
BOOL PacketQueueEnq(packet_t* pkt);

//包出队
packet_t* PacketQueueDeq();

//销毁队列
void PacketQueueDes();