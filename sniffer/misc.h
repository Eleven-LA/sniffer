#pragma once
#include"framework.h"


//���Ժ���
void OutputDbgInfo(const CHAR* format, ...);

//char*תwchar*
wchar_t* AnsiToUnicode(const char* szStr);

//wchar*תchar*
char* UnicodeToAnsi(const wchar_t* szStr);
