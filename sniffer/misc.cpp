#include "misc.h"

/*-----------------------------------------------------杂七杂八的函数--------------------------------------------------------*/

//输出调试函数
void OutputDbgInfo(const CHAR* format, ...)
{
    CHAR szData[512] = { 0 };
    va_list arg;

    va_start(arg, format);
    vsprintf(szData, format, arg);
    //_vsntprintf(szData, sizeof(szData) - 1, format, arg);这个可以用来打印wchar的字符串，要记得把char都改成tchar，用outputdebugstringw
    va_end(arg);

    OutputDebugStringA(szData);
}

wchar_t* AnsiToUnicode(const char* szStr)
{
    int nLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, NULL, 0);
    if (nLen == 0)
    {
        return NULL;
    }
    wchar_t* pResult = new wchar_t[nLen];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, pResult, nLen);
    return pResult;
}

char* UnicodeToAnsi(const wchar_t* szStr)
{
    int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)
    {
        return NULL;
    }
    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
    return pResult;
}