// sniffer.cpp : 定义应用程序的入口点。
//

#include "sniffer.h"



// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名
pcap_if_t* alldevs;//设备指针
BOOL bStopFlag;//停止标识
parsed_packet* parsed_cur;//解析后的数据包
parsed_packet* parsed_pkts;//解析后的数据包
pkt_count* n_packet;//统计各类包的数量
int pktNum;//包编号

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    

    // 初始化全局字符串
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_SNIFFER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SNIFFER));

    MSG msg;

    // 主消息循环:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SNIFFER));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_SNIFFER);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 将实例句柄存储在全局变量中

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        {
            DialogBox(hInst, MAKEINTRESOURCE(IDD_SNIFFER_DIALOG), hWnd, MainDiaLogProc);//主窗口直接弹对话框
        }
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // 分析菜单选择:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, AboutDiaLogProc);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

//主对话框消息处理
INT_PTR CALLBACK MainDiaLogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
        case WM_INITDIALOG:
        {
            //加载用到的类
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_WIN95_CLASSES;
            InitCommonControlsEx(&icex);

            //初始化包显示列表
            InitPacketListView(hDlg);
        
            //获取网卡列表并显示在下拉列表
            alldevs = FindAllDevs();
            if (alldevs == NULL) return (INT_PTR)TRUE;
            pcap_if_t* d;
            WCHAR* devname;
            HWND hComboBox = GetDlgItem(hDlg, IDC_COMBO_INTERFACE);
            for (d = alldevs; d; d = d->next)
            {
                devname = AnsiToUnicode(d->description);
                SendMessage(hComboBox, CB_ADDSTRING, NULL, (LPARAM)devname);
            }
            SendMessage(hComboBox, CB_SETCURSEL, 0, 0);//默认显示第一行

            //没有抓包，禁用停止按钮
            EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_STOP), FALSE);

            //创建暂存文件夹
            CreateFolder();
            return (INT_PTR)TRUE;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDC_BUTTON_START:
                {
                
                    SendMessage(GetDlgItem(hDlg,IDC_LIST_PACKET), LVM_DELETEALLITEMS, 0, 0);//清除原有数据
                    bStopFlag = FALSE;//设置停止位
                    PacketQueueInit();//初始化包序列
                    HWND hComboBox = GetDlgItem(hDlg, IDC_COMBO_INTERFACE);
                    if (SendMessage(hComboBox, CB_GETCOUNT, NULL, 0) == 0) {
                        MessageBox(NULL, _T("网卡，网卡，你网卡呢？"), _T("Error"), MB_OK);
                        return (INT_PTR)TRUE;
                    }
                    int index = SendMessage(hComboBox, CB_GETCURSEL, NULL, 0);//获取当前选中网卡
                    CaptureArg myCaptureArg = {};
                    myCaptureArg.index = index;
                    myCaptureArg.alldevs = alldevs;
                    myCaptureArg.hDlg = hDlg;
                    HANDLE hCaputreThread = CreateThread(0, 0, Capture, &myCaptureArg, 0, 0);//启动捕获线程
                    HANDLE hParesThread = CreateThread(0, 0, Parse, &hDlg, 0, 0);//启动解析线程
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_STOP), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_START), FALSE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_READ), FALSE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_SAVE), FALSE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_COMMIT), FALSE);
                    break;
                }
                case IDC_BUTTON_STOP:
                {
                    bStopFlag = TRUE;
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_START), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_READ), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_SAVE), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_STOP), FALSE);
                    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_COMMIT), TRUE);
                    break;
                }
                case IDC_BUTTON_SAVE:
                {
                    if(!TempFilePath[0])
                    {
                        MessageBox(NULL, _T("你都没数据，保存个der"), _T("Error"), MB_OK);
                        break;
                    }
                    TCHAR szBuffer[MAX_PATH] = { 0 };
                    BROWSEINFO bi;
                    ZeroMemory(&bi, sizeof(BROWSEINFO));
                    bi.hwndOwner = NULL;
                    bi.pszDisplayName = szBuffer;
                    bi.lpszTitle = _T("请选择数据包存放位置:");
                    bi.ulFlags = BIF_RETURNFSANCESTORS;
                    LPITEMIDLIST idl = SHBrowseForFolder(&bi);
                    if (idl == NULL)
                    {
                        MessageBox(NULL, _T("不选择文件夹你让我存哪儿？"), _T("Error"), MB_OK);
                        break;
                    }
                    SHGetPathFromIDList(idl, szBuffer);
                    char* filename = strstr(TempFilePath, "\\");
                    lstrcatW(szBuffer, AnsiToUnicode(filename));
                    if(!CopyFile(AnsiToUnicode(TempFilePath), szBuffer, TRUE)) MessageBox(NULL, _T("保存失败，寄"), _T("Error"), MB_OK);;
                    break;
                }
                case IDC_BUTTON_READ:
                {
                    TCHAR szFileName[MAX_PATH];
                    OPENFILENAME stOpenFile;//查看pe文件时弹出的对话框结构体
                    TCHAR szPeFileExt[100] = _T("*.libpcap");
                    memset(szFileName, 0, MAX_PATH);
                    memset(&stOpenFile, 0, sizeof(OPENFILENAME));
                    stOpenFile.lStructSize = sizeof(OPENFILENAME);
                    stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                    stOpenFile.hwndOwner = hDlg;
                    stOpenFile.lpstrFilter = szPeFileExt;
                    stOpenFile.lpstrFile = szFileName;
                    stOpenFile.nMaxFile = MAX_PATH;
                    char cur[MAX_PATH];//当前目录
                    if (getcwd(cur, MAX_PATH) == FALSE) {
                        MessageBox(NULL, _T("获取目录失败，我也不知道啥问题，先寄为敬"), _T("Error"), MB_OK);
                        ExitProcess(-1);
                    }
                    GetOpenFileName(&stOpenFile);//这个操作会改变工作目录，需要自己保存和切换目录才不会使程序的目录跑飞，目录跑飞会导致保存失败，因为写的不是绝对路径
                    if (szFileName[0] != '\0')      //若未能获取到用户想读取的文件路径，则不进行操作
                    {
                        char* filepath = UnicodeToAnsi(szFileName);
                        if (!strstr(filepath, ".libpcap")) {
                            MessageBox(NULL, _T("你怎么敢拿其他文件来糊弄我呀，我只能解析.libpcap后缀"), _T("Warning"), MB_OK);
                            break;
                        }
                        char filename[30] ;//让读取到的数据包也支持另存为
                        strcpy(filename,strrchr(filepath, '\\'));
                        strcpy(TempFilePath, DIRNAME);
                        strcat(TempFilePath, filename);
                        ReadPacketFile(filepath,hDlg);
                        if (chdir(cur)) {
                            MessageBox(NULL, _T("目录怎么切不回去了啊！！!寄"), _T("Error"), MB_OK);
                            ExitProcess(-1);
                        }
                        return (INT_PTR)TRUE;
                    }
                    if (chdir(cur)) {
                        MessageBox(NULL, _T("目录怎么切不回去了啊！！!寄"), _T("Error"), MB_OK);
                        ExitProcess(-1);
                    }
                    break;
                }

                case IDCANCEL: 
                {
                    int x = remove(TempFilePath);//清除临时文件
                    if(x==-1) MessageBox(NULL, _T("没有权限帮宁清除缓存文件呢，自己动手删叭"), _T("Warning"), MB_OK);
                    ExitProcess(0);
                }
               
                    
            }
        break;   
        }
        case WM_NOTIFY:
        {
            NMHDR* pNMHDR = (NMHDR*)lParam;
            if (wParam == IDC_LIST_PACKET && pNMHDR->code == NM_CLICK)
            {
                //显示详细数据
                ShowPktDetail(hDlg);
                return (INT_PTR)TRUE;
            }
        break;
        }
    }
    return (INT_PTR)FALSE;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK AboutDiaLogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

//初始化包列表显示
void InitPacketListView(HWND hDlg) 
{
    LV_COLUMN lv;
    HWND hListPacket;

    //初始化
    memset(&lv, 0, sizeof(LV_COLUMN));

    //获取句柄
    hListPacket = GetDlgItem(hDlg, IDC_LIST_PACKET);

    //设置整行选中
    SendMessage(hListPacket, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("序号");
    lv.cx = 50;
    lv.iSubItem = 0;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    //第二列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("时间");
    lv.cx = 200;
    lv.iSubItem = 1;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

    //第三列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("源IP");
    lv.cx = 150;
    lv.iSubItem = 2;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 2, (DWORD)&lv);

    //第四列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("目的IP");
    lv.cx = 150;
    lv.iSubItem = 3;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

    //第五列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("长度");
    lv.cx = 50;
    lv.iSubItem = 4;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 4, (DWORD)&lv);

    //第六列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("协议");
    lv.cx = 50;
    lv.iSubItem = 5;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

    //第七列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("源MAC");
    lv.cx = 200;
    lv.iSubItem = 6;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 6, (DWORD)&lv);

    //第八列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = (LPWSTR)_T("目的MAC");
    lv.cx = 200;
    lv.iSubItem = 7;
    SendMessage(hListPacket, LVM_INSERTCOLUMN, 7, (DWORD)&lv);
    return;
}

void ReadPacketFile(char* filepath,HWND hDlg) {
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;
    if (!LoadNpcapDlls())
    {
        MessageBox(NULL, _T("加载Npcap失败，宁的程序啥也干不了，帮宁退出了"), _T("Error"), MB_OK);
        ExitProcess(-1);
    }

   
    if (pcap_createsrcstr(source, // variable that will keep the source string
        PCAP_SRC_FILE,  // we want to open a file
        NULL,      // remote host
        NULL,      // port on the remote host
        filepath,    // name of the file we want to open
        errbuf      // error buffer
    ) != 0)
    {
        MessageBox(NULL, _T("创建source string失败了"), _T("Error"), MB_OK);
        return ;
    }

    if ((fp = pcap_open(source, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet
               // will be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // authentication on the remote machine
        errbuf // error buffer
    )) == NULL)
    {
        MessageBox(NULL, _T("阿发你小子在搞什么，文件怎么打不开啊"), _T("Error"), MB_OK);
        return ;
    }
    SendMessage(GetDlgItem(hDlg, IDC_LIST_PACKET), LVM_DELETEALLITEMS, 0, 0);//清除原有数据
    //初始化解析所需变量
    if (parsed_pkts == NULL)  parsed_pkts = (parsed_packet*)malloc(1000000 * sizeof(parsed_packet));
    parsed_cur = parsed_pkts;
    n_packet = (pkt_count*)malloc(sizeof(pkt_count));
    packet_t* pkt = (packet_t*)malloc(sizeof(packet_t));
    if (parsed_cur == NULL || n_packet == NULL||pkt==NULL) {
        MessageBox(NULL, _T("分配内存出错,停止包解析"), _T("Error"), MB_OK);
        ExitThread(-1);
    }
    memset(parsed_pkts, 0, 1000000 * sizeof(parsed_packet));
    memset(n_packet, 0, sizeof(pkt_count));
    pktNum = 0;
    //开始解析
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        if (pktNum > 1000000) {
            MessageBox(NULL, _T("内存中数据包太多我顶不住啦"), _T("Error"), MB_OK);
            break;
        }
        pkt->header = header;
        pkt->pkt_data =(u_char*) pkt_data;
        PreAnalyze(pkt);
        if (!AnalyzeEth(pkt->pkt_data)) continue;	//无法解析就跳过该包
        //显示解析得到的数据
        ShwoPktInfo(GetDlgItem(hDlg,IDC_LIST_PACKET));
        ShowPktCount(hDlg);
        parsed_cur++;
        pktNum++;
    }

    free(n_packet);
    return ;
}


