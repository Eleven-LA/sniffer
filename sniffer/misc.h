#pragma once
#include"framework.h"


//调试函数
void OutputDbgInfo(const CHAR* format, ...);

//char*转wchar*
wchar_t* AnsiToUnicode(const char* szStr);

//wchar*转char*
char* UnicodeToAnsi(const wchar_t* szStr);
