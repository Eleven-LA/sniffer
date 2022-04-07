#include "capture.h"
#include "misc.h"
#include "packetque.h"
#include "sniffer.h"
/*-----------------------------------------------------捕捉器--------------------------------------------------------*/

char TempFilePath[50];

DWORD WINAPI Capture(PVOID pParam)
{
    CaptureArg* myCaptureArg = (CaptureArg*)pParam;
    pcap_if_t* d;

    int i=0 ;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

   //跳转到所选适配器
    for (d = myCaptureArg->alldevs; i <myCaptureArg->index ; d = d->next, i++) ;

    //开启设备
    if ((adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet will
               // be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // authentication on the remote machine
        errbuf // error buffer
    )) == NULL)
    {
        MessageBox(NULL, _T("无法打开网络适配器，部分功能可能无法正常使用"), _T("Error"), MB_OK);
        //异常退出的话要把按钮恢复一下
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
        return -1;
    }
    //获取并设置过滤表达式，如果有的话
    TCHAR filterstr[50];
    memset(filterstr, 0,50);
    if (GetWindowText(GetDlgItem(myCaptureArg->hDlg, IDC_EDIT_FILTER), filterstr, 50)) {
        bpf_u_int32 netmask;
        struct bpf_program fcode;
        if (d->addresses != NULL) netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else netmask = 0xffffff;

        if (pcap_compile(adhandle, &fcode, UnicodeToAnsi(filterstr), 1, netmask) < 0)
        {
            MessageBox(NULL, _T("表达式写错啦！！！"), _T("Error"), MB_OK);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
            return -1;
        }

        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            MessageBox(NULL, _T("过滤器设置出问题了，我也不知道怎么解决，开摆"), _T("Error"), MB_OK);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
            return -1;
        }
    }

    //创建暂存文件夹
    CreateFolder();
    //创建临时文件路径
    CreateTempFilePath();
    //打开临时文件
    pcap_dumper_t* dumpfile = pcap_dump_open(adhandle, TempFilePath);
    //开始捕获
    pcap_loop(adhandle, 0, PacketHandler, (unsigned char*)dumpfile);

    return 0;
}

//获取网卡信息
pcap_if_t* FindAllDevs()
{
    pcap_if_t* alldevs=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        MessageBox(NULL, _T("加载Npcap失败，宁的程序啥也干不了，帮宁退出了"), _T("Error"), MB_OK);
        ExitProcess(-1);
    }
    //获取设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        MessageBox(NULL, _T("获取网卡出现错误，部分功能可能无法正常使用"), _T("Error"), MB_OK);
        return NULL;
    }
    return alldevs;
}

//包处理回调
void PacketHandler(u_char* dumpfile,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    if (bStopFlag) ExitThread(0);
    packet_t* pkt = (packet_t*)malloc(sizeof(packet_t));
    if (pkt) {
        pkt->header = (pcap_pkthdr*)header;
        pkt->pkt_data = (u_char*)pkt_data;
        pkt->packet_next = NULL;
        PacketQueueEnq(pkt);
    }
    else{
        MessageBox(NULL, _T("内存空间不足"), _T("Error"), MB_OK);
        //停止捕获
        ExitThread(-1);
    }
    pcap_dump(dumpfile, header, pkt_data);//将包保存到临时文件
    return;
}

//设置dll目录
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        OutputDbgInfo("Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        OutputDbgInfo("Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}

//创建暂存文件夹
void CreateFolder()
{
    //文件夹名称
    char folderName[] = DIRNAME;

    // 文件夹不存在则创建文件夹
    if (_access(folderName, 0) == -1)
    {
        if (_mkdir(folderName)==-1) {
            MessageBox(NULL, _T("文件夹创建失败，程序寄了"), _T("Error"), MB_OK);
            ExitProcess(-1);
        }
    }
    return ;
}

void CreateTempFilePath()
{
    memset(TempFilePath, 50, 0);
    char thistime[30];
    struct tm* ltime;
    time_t nowtime;
    time(&nowtime);
    ltime = localtime(&nowtime);
    strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
    strcpy(TempFilePath, DIRNAME);
    strcat(TempFilePath, "\\");
    strcat(TempFilePath, thistime);
    strcat(TempFilePath, ".libpcap");
    return ;
}


