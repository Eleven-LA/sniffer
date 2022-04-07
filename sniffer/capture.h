#pragma once
#include "framework.h"

#define DIRNAME "TempData"	//��ʱ�ļ����ļ�����

//��ʱ�ļ�·��
extern char TempFilePath[50];

//capture�̲߳����ṹ��
typedef struct CaptureArg {
	int index;//�����±�
	pcap_if_t* alldevs;//�豸��
	HWND hDlg;//�����ڶԻ���
}CaptureArg;

//������
DWORD WINAPI Capture(PVOID pParam);

//��ȡ������Ϣ
pcap_if_t* FindAllDevs();

//������ص�����
void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

//����npcap��dll
BOOL LoadNpcapDlls();

//�����ݴ��ļ���
void CreateFolder();

//������ʱ�ļ�·��
void CreateTempFilePath();



