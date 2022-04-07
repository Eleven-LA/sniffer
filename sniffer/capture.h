#pragma once
#include "framework.h"

#define DIRNAME "TempData"	//临时文件的文件夹名

//临时文件路径
extern char TempFilePath[50];

//capture线程参数结构体
typedef struct CaptureArg {
	int index;//网卡下标
	pcap_if_t* alldevs;//设备链
	HWND hDlg;//主窗口对话框
}CaptureArg;

//捕获函数
DWORD WINAPI Capture(PVOID pParam);

//获取网卡信息
pcap_if_t* FindAllDevs();

//包处理回调函数
void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

//加载npcap的dll
BOOL LoadNpcapDlls();

//创建暂存文件夹
void CreateFolder();

//构造临时文件路径
void CreateTempFilePath();



