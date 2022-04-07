#include "capture.h"
#include "misc.h"
#include "packetque.h"
#include "sniffer.h"
/*-----------------------------------------------------��׽��--------------------------------------------------------*/

char TempFilePath[50];

DWORD WINAPI Capture(PVOID pParam)
{
    CaptureArg* myCaptureArg = (CaptureArg*)pParam;
    pcap_if_t* d;

    int i=0 ;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

   //��ת����ѡ������
    for (d = myCaptureArg->alldevs; i <myCaptureArg->index ; d = d->next, i++) ;

    //�����豸
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
        MessageBox(NULL, _T("�޷������������������ֹ��ܿ����޷�����ʹ��"), _T("Error"), MB_OK);
        //�쳣�˳��Ļ�Ҫ�Ѱ�ť�ָ�һ��
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
        EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
        return -1;
    }
    //��ȡ�����ù��˱��ʽ������еĻ�
    TCHAR filterstr[50];
    memset(filterstr, 0,50);
    if (GetWindowText(GetDlgItem(myCaptureArg->hDlg, IDC_EDIT_FILTER), filterstr, 50)) {
        bpf_u_int32 netmask;
        struct bpf_program fcode;
        if (d->addresses != NULL) netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else netmask = 0xffffff;

        if (pcap_compile(adhandle, &fcode, UnicodeToAnsi(filterstr), 1, netmask) < 0)
        {
            MessageBox(NULL, _T("���ʽд����������"), _T("Error"), MB_OK);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
            return -1;
        }

        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            MessageBox(NULL, _T("���������ó������ˣ���Ҳ��֪����ô���������"), _T("Error"), MB_OK);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_START), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_READ), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_SAVE), TRUE);
            EnableWindow(GetDlgItem(myCaptureArg->hDlg, IDC_BUTTON_STOP), FALSE);
            return -1;
        }
    }

    //�����ݴ��ļ���
    CreateFolder();
    //������ʱ�ļ�·��
    CreateTempFilePath();
    //����ʱ�ļ�
    pcap_dumper_t* dumpfile = pcap_dump_open(adhandle, TempFilePath);
    //��ʼ����
    pcap_loop(adhandle, 0, PacketHandler, (unsigned char*)dumpfile);

    return 0;
}

//��ȡ������Ϣ
pcap_if_t* FindAllDevs()
{
    pcap_if_t* alldevs=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        MessageBox(NULL, _T("����Npcapʧ�ܣ����ĳ���ɶҲ�ɲ��ˣ������˳���"), _T("Error"), MB_OK);
        ExitProcess(-1);
    }
    //��ȡ�豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        MessageBox(NULL, _T("��ȡ�������ִ��󣬲��ֹ��ܿ����޷�����ʹ��"), _T("Error"), MB_OK);
        return NULL;
    }
    return alldevs;
}

//������ص�
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
        MessageBox(NULL, _T("�ڴ�ռ䲻��"), _T("Error"), MB_OK);
        //ֹͣ����
        ExitThread(-1);
    }
    pcap_dump(dumpfile, header, pkt_data);//�������浽��ʱ�ļ�
    return;
}

//����dllĿ¼
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

//�����ݴ��ļ���
void CreateFolder()
{
    //�ļ�������
    char folderName[] = DIRNAME;

    // �ļ��в������򴴽��ļ���
    if (_access(folderName, 0) == -1)
    {
        if (_mkdir(folderName)==-1) {
            MessageBox(NULL, _T("�ļ��д���ʧ�ܣ��������"), _T("Error"), MB_OK);
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


