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
extern parsed_packet* parsed_cur;//解析后的数据包
extern parsed_packet* parsed_pkts;//解析后的数据包
extern pkt_count* n_packet;//统计各类包的数量
extern int pktNum;//包编号

//原有的函数
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    AboutDiaLogProc(HWND, UINT, WPARAM, LPARAM);

//主对话框回调
INT_PTR CALLBACK    MainDiaLogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//初始化包显示列表
void InitPacketListView(HWND hDlg);

void ReadPacketFile(char* filename, HWND hDlg);