// header.h: 标准系统包含文件的包含文件，
// 或特定于项目的包含文件
//
#pragma warning(disable : 4996)
#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>
// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <tchar.h>
#include <stdarg.h>
#include<stdio.h>
#include<time.h>
#include<direct.h>
#include <shlobj.h>
#include <commdlg.h>
//pcap头文件
#include<pcap.h>
//通用控件所需lib
#include <CommCtrl.h>
#pragma comment(lib,"comctl32.lib")
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
//npcap的所需lib
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma   comment   (lib,"Ws2_32.lib")
