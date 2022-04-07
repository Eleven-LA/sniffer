#include"packetque.h"
#include"misc.h"

/*-----------------------------------------------------������--------------------------------------------------------*/

static unsigned int que_len = 0;//���г���
static packet_t* pkt_header = NULL;//ͷָ��
static packet_t* pkt_tail = NULL;//βָ��
CRITICAL_SECTION cs;//�߳���

void PacketQueueInit()
{
	pkt_header = NULL;
	pkt_tail = NULL;
	que_len = 0;
	InitializeCriticalSection(&cs);
	return ;
}

BOOL PacketQueueEnq(packet_t* pkt)
{
	EnterCriticalSection(&cs);
	if (que_len == 0)
	{
		pkt_header = pkt;
		pkt_tail = pkt;
		pkt->packet_next = NULL;
		que_len++;
		//OutputDbgInfo("header:%c\ndata:%c\n", pkt->header, pkt->pkt_data);
		LeaveCriticalSection(&cs);
		return TRUE;
	}
	if (que_len > 100000) {		//�ڴ������ݰ�����ʱ��ֹͣ����
		MessageBox(NULL, _T("���������ݰ��ۻ����ֹ࣬ͣ����"), _T("Error"), MB_OK);
		//ֹͣ������
		LeaveCriticalSection(&cs);
		ExitThread(-1);
	}
	pkt_tail->packet_next = pkt;
	pkt_tail = pkt;
	pkt->packet_next = NULL;
	que_len++;
	LeaveCriticalSection(&cs);
	return TRUE;
}

packet_t* PacketQueueDeq()
{
	EnterCriticalSection(&cs);
	packet_t* pkt;
	if (que_len == 0) {
		LeaveCriticalSection(&cs);
		return NULL;
	}
	else if (que_len == 1) pkt_tail = NULL;//ֻ��һ����Ҫ��βָ���ÿ�
	pkt = pkt_header;
	pkt_header = pkt_header->packet_next;
	que_len--;
	LeaveCriticalSection(&cs);
	return pkt;
}

void PacketQueueDes()
{
	EnterCriticalSection(&cs);
	packet_t* pkt;
	while (que_len > 0)
	{
		pkt = pkt_header;
		pkt_header = pkt_header->packet_next;
		free(pkt);
		que_len--;
	}
	pkt_header = NULL;
	pkt_tail = NULL;
	que_len = 0;
	LeaveCriticalSection(&cs);
	DeleteCriticalSection(&cs);
	return ;
}