#pragma once
#pragma warning(disable:4996)
#include "resource.h"
#include "framework.h"
#include "capture.h"
#include "packetque.h"
#include "misc.h"
#include "parse.h"

#define MAX_LOADSTRING 100


extern BOOL bStopFlag;
extern parsed_packet* parsed_cur;//����������ݰ�
extern parsed_packet* parsed_pkts;//����������ݰ�
extern pkt_count* n_packet;//ͳ�Ƹ����������
extern int pktNum;//�����

//ԭ�еĺ���
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    AboutDiaLogProc(HWND, UINT, WPARAM, LPARAM);

//���Ի���ص�
INT_PTR CALLBACK    MainDiaLogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//��ʼ������ʾ�б�
void InitPacketListView(HWND hDlg);

void ReadPacketFile(char* filename, HWND hDlg);