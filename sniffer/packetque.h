#pragma once
#include"framework.h"

//�����е����ݰ��ṹ
typedef struct packet {
	pcap_pkthdr* header;//ָ�����������
	u_char* pkt_data;//ָ�������
	packet* packet_next;//ָ����һ�����ݰ��ṹ
}packet_t;

//��ʼ�����ݰ�����
void PacketQueueInit();

//�����
BOOL PacketQueueEnq(packet_t* pkt);

//������
packet_t* PacketQueueDeq();

//���ٶ���
void PacketQueueDes();