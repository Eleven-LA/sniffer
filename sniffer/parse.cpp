#include"parse.h"
#include"misc.h"
#include"sniffer.h"
/*-----------------------------------------------------包解析--------------------------------------------------------*/



DWORD WINAPI Parse(PVOID pParam)
{

	HWND hDlg = *(HWND*)pParam;
	HWND hPktInfo = GetDlgItem(hDlg, IDC_LIST_PACKET);//获取包信息列表
	
	//为避免malloc开销过大，若分配过了就不再重新分配，直接覆盖原有数据,这个分配的堆数据不会被回收，固定作为程序中解析后包存放的位置，直到程序结束
	if(parsed_pkts == NULL)  parsed_pkts = (parsed_packet*)malloc(1000000 * sizeof(parsed_packet));
	
	parsed_cur = parsed_pkts;
	n_packet = (pkt_count*)malloc(sizeof(pkt_count));
	
	if (parsed_cur == NULL|| n_packet==NULL) {
		MessageBox(NULL, _T("分配内存出错,停止包解析"), _T("Error"), MB_OK);
		ExitThread(-1);
	}

	memset(parsed_pkts, 0, 1000000 * sizeof(parsed_packet));
	memset(n_packet, 0, sizeof(pkt_count));
	pktNum = 0;

	while (1) {
		if (pktNum > 1000000) {
			MessageBox(NULL, _T("内存中数据包太多我顶不住啦"), _T("Error"), MB_OK);
			break;
		}
		packet_t* pkt = PacketQueueDeq();
		if (pkt == NULL) {
			if (bStopFlag) {

				break; //已经解析完所有数据且停止位为1时就退出
			}
			continue;//没取到数据就不解析，如需处理无法解析的数据包可在此处添加代码
		}
		PreAnalyze(pkt);
		if(!AnalyzeEth(pkt->pkt_data)) continue;	//无法解析就跳过该包
		//显示解析得到的数据
		ShwoPktInfo(hPktInfo);	
		ShowPktCount(hDlg);
		parsed_cur++;
		pktNum++;
	}

	free(n_packet);
	PacketQueueDes();
	return 0;

}

void PreAnalyze(packet_t* pkt)
{
	struct tm ltime;
	time_t local_tv_sec;
	parsed_cur->len = pkt->header->len;//长度
	local_tv_sec = pkt->header->ts.tv_sec;//时间
	localtime_s(&ltime, &local_tv_sec);
	parsed_cur->time[0] = ltime.tm_year + 1900;
	parsed_cur->time[1] = ltime.tm_mon + 1;
	parsed_cur->time[2] = ltime.tm_mday;
	parsed_cur->time[3] = ltime.tm_hour;
	parsed_cur->time[4] = ltime.tm_min;
	parsed_cur->time[5] = ltime.tm_sec;
	parsed_cur->rawdata = pkt->pkt_data;//原始数据指针
	return;
}

BOOL AnalyzeEth(u_char* pkt)
{
	eth_header* ethh = (eth_header*)pkt;
	for (int i = 0; i < 6; i++)
	{
		parsed_cur->ethh.dest[i] = ethh->dest[i];
		parsed_cur->ethh.src[i] = ethh->src[i];
	}

	n_packet->n_total ++;
	//网络字节顺序转主机字节顺序
	parsed_cur->ethh.type = ntohs(ethh->type);
	//解析上一层
	switch (parsed_cur->ethh.type)
	{
	case PROTO_ARP:
		AnalyzeArp((u_char*)pkt + 14);      //mac 头大小为14
		break;
	case PROTO_IPV4:
		return AnalyzeIpv4((u_char*)pkt + 14);
	case PROTO_IPV6:
		return AnalyzeIpv6((u_char*)pkt + 14);
	default:	//无法解析
		return FALSE;
	}
	return TRUE;
}

void AnalyzeArp(u_char* pkt)
{
	arp_header* arph = (arp_header*)pkt;
	n_packet->n_arp++;
	parsed_cur->arph.hrd = ntohs(arph->hrd);
	parsed_cur->arph.protocol = ntohs(arph->protocol);
	parsed_cur->arph.hrdlen = arph->hrdlen;
	parsed_cur->arph.prolen = arph->prolen;
	parsed_cur->arph.opcode = ntohs(arph->opcode);
	//复制IP及MAC
	for (int i = 0; i < 6; i++)
	{
		if (i < 4)
		{
			parsed_cur->arph.destip[i] = arph->destip[i];
			parsed_cur->arph.srcip[i] = arph->srcip[i];
		}
		parsed_cur->arph.destmac[i] = arph->destmac[i];
		parsed_cur->arph.srcmac[i] = arph->srcmac[i];
	}

	strcpy(parsed_cur->pktType, "ARP");
	return ;
}

BOOL AnalyzeIpv4(u_char* pkt)
{
	ipv4_header* ipv4h = (ipv4_header*)pkt;
	n_packet->n_ipv4++;
	parsed_cur->ipv4h.headerlen = ipv4h->headerlen;
	parsed_cur->ipv4h.version = ipv4h->version;
	parsed_cur->ipv4h.tos = ipv4h->tos;
	parsed_cur->ipv4h.totallen = ntohs(ipv4h->totallen);
	parsed_cur->ipv4h.flag = ipv4h->flag;
	parsed_cur->ipv4h.fragoffset = ipv4h->fragoffset;
	parsed_cur->ipv4h.ttl = ipv4h->ttl;
	parsed_cur->ipv4h.protocol = ipv4h->protocol;
	parsed_cur->ipv4h.checksum = ipv4h->checksum;
	parsed_cur->ipv4h.srcip = ipv4h->srcip;
	parsed_cur->ipv4h.destip = ipv4h->destip;
	parsed_cur->ipv4h.option = ipv4h->option;

	switch (ipv4h->protocol)
	{
	case PROTO_ICMP:
		AnalyzeIcmp((u_char*)ipv4h + ipv4h->headerlen *4);	//包头的单位是4字节
		break;
	case PROTO_TCP:
		AnalyzeTcp((u_char*)ipv4h + ipv4h->headerlen * 4);
		break;
	case PROTO_UDP:
		AnzlyzeUdp((u_char*)ipv4h + ipv4h->headerlen * 4);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

BOOL AnalyzeIpv6(u_char* pkt)
{

	ipv6_header* iph6 = (ipv6_header*)pkt;
	n_packet->n_ipv6++;

	parsed_cur->ipv6h.version = iph6->version;
	parsed_cur->ipv6h.flowtype = iph6->flowtype;
	parsed_cur->ipv6h.flowid = iph6->flowid;
	parsed_cur->ipv6h.payloadlen = ntohs(iph6->payloadlen);
	parsed_cur->ipv6h.nexthead = iph6->nexthead;
	parsed_cur->ipv6h.hoplimit = iph6->hoplimit;

	for (int i = 0; i < 8; i++)
	{
		parsed_cur->ipv6h.srcaddr[i] = iph6->srcaddr[i];
		parsed_cur->ipv6h.destaddr[i] = iph6->destaddr[i];
	}

	switch (iph6->nexthead)
	{
	case PROTO_TCP:
		AnalyzeTcp((u_char*)iph6 + 40);
	case PROTO_UDP:
		AnzlyzeUdp((u_char*)iph6 + 40);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

void AnalyzeIcmp(u_char* pkt)
{
	icmp_header* icmph = (icmp_header*)pkt;
	n_packet->n_icmp++;
	parsed_cur->icmph.checksum = icmph->checksum;
	parsed_cur->icmph.code = icmph->code;
	parsed_cur->icmph.seq = icmph->seq;
	parsed_cur->icmph.type = icmph->type;
	strcpy(parsed_cur->pktType, "ICMP");
	return ;
}

void AnalyzeTcp(u_char* pkt)
{
	tcp_header* tcph = (tcp_header*)pkt;
	n_packet->n_tcp++;
	parsed_cur->tcph.srcport = ntohs(tcph->srcport);
	parsed_cur->tcph.destport = ntohs(tcph->destport);
	parsed_cur->tcph.seq = tcph->seq;
	parsed_cur->tcph.ack = tcph->ack;
	parsed_cur->tcph.headlen = tcph->headlen;
	parsed_cur->tcph.fin = tcph->fin;
	parsed_cur->tcph.syn = tcph->syn;
	parsed_cur->tcph.rst = tcph->rst;
	parsed_cur->tcph.psh = tcph->psh;
	parsed_cur->tcph.ackbit = tcph->ackbit;
	parsed_cur->tcph.urg = tcph->urg;
	parsed_cur->tcph.ece = tcph->ece;
	parsed_cur->tcph.cwr = tcph->cwr;
	parsed_cur->tcph.winsize = tcph->winsize;
	parsed_cur->tcph.checksum = tcph->checksum;
	parsed_cur->tcph.urgptr = tcph->urgptr;

	if (ntohs(tcph->destport) == 80 || ntohs(tcph->srcport) == 80|| ntohs(tcph->destport) == 8080 || ntohs(tcph->srcport) == 8080)
	{
		n_packet->n_http++;
		strcpy(parsed_cur->pktType, "HTTP");
	}
	else if (ntohs(tcph->destport) == 443 || ntohs(tcph->srcport) == 443)
	{
		n_packet->n_https++;
		strcpy(parsed_cur->pktType, "HTTPS");
	}
	else {
		n_packet->n_tcp++;
		strcpy(parsed_cur->pktType, "TCP");
	}
	return ;
}

void AnzlyzeUdp(u_char* pkt)
{
	udp_header* udph = (udp_header*)pkt;
	n_packet->n_udp++;
	parsed_cur->udph.checksum = udph->checksum;
	parsed_cur->udph.destport = ntohs(udph->destport);
	parsed_cur->udph.len = ntohs(udph->len);
	parsed_cur->udph.srcport = ntohs(udph->srcport);
	strcpy(parsed_cur->pktType, "UDP");

	return ;
}

void ShwoPktInfo(HWND hPktInfo)
{
	LV_ITEM vitem;
	TCHAR buffer[50];
	vitem.mask = LVIF_TEXT;
	vitem.pszText = buffer;

	int pos = ListView_GetItemCount(hPktInfo);//获取插入行位置
	//序列号
	wsprintf(vitem.pszText, TEXT("%d"), pktNum);
	vitem.iItem = pos;    //行
	vitem.iSubItem = 0; //列
	ListView_InsertItem(hPktInfo, &vitem);  //发送消息，宏定义,每一行的第一列都要用insertitem，后面的行用setitem

	//时间戳
	wsprintf(vitem.pszText, TEXT("%d/%d/%d  %d:%d:%d"), parsed_cur->time[0], parsed_cur->time[1],parsed_cur->time[2],
		parsed_cur->time[3], parsed_cur->time[4], parsed_cur->time[5]);
	vitem.iItem = pos;    //行
	vitem.iSubItem = 1; //列
	ListView_SetItem(hPktInfo, &vitem);

	//ip
	switch (parsed_cur->ethh.type) {
		case PROTO_ARP:
		{
			wsprintf(vitem.pszText, TEXT("%d.%d.%d.%d"),parsed_cur->arph.srcip[0], parsed_cur->arph.srcip[1],
				parsed_cur->arph.srcip[2], parsed_cur->arph.srcip[3]);
			vitem.iItem = pos;    //行
			vitem.iSubItem = 2; //列
			ListView_SetItem(hPktInfo, &vitem);

			wsprintf(vitem.pszText, TEXT("%d.%d.%d.%d"), parsed_cur->arph.destip[0], parsed_cur->arph.destip[1],
				parsed_cur->arph.destip[2], parsed_cur->arph.destip[3]);
			vitem.iItem = pos;    //行
			vitem.iSubItem = 3; //列
			ListView_SetItem(hPktInfo, &vitem);
		}
		break;
		case PROTO_IPV4:
		{
			struct  in_addr in;
			in.S_un.S_addr = parsed_cur->ipv4h.srcip;
			wsprintf(vitem.pszText, TEXT("%s%"), AnsiToUnicode(inet_ntoa(in)));
			vitem.iItem = pos;    //行
			vitem.iSubItem = 2; //列
			ListView_SetItem(hPktInfo, &vitem);

			in.S_un.S_addr = parsed_cur->ipv4h.destip;
			wsprintf(vitem.pszText, TEXT("%s%"), AnsiToUnicode(inet_ntoa(in)));
			vitem.iItem = pos;    //行
			vitem.iSubItem = 3; //列
			ListView_SetItem(hPktInfo, &vitem);
		}
		break;
		case PROTO_IPV6:
		{
			wsprintf(vitem.pszText, TEXT("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"), parsed_cur->ipv6h.srcaddr[0], parsed_cur->ipv6h.srcaddr[1],
				parsed_cur->ipv6h.srcaddr[2], parsed_cur->ipv6h.srcaddr[3], parsed_cur->ipv6h.srcaddr[4], parsed_cur->ipv6h.srcaddr[5],
				parsed_cur->ipv6h.srcaddr[6], parsed_cur->ipv6h.srcaddr[7]);
			vitem.iItem = pos;    //行
			vitem.iSubItem = 2; //列
			ListView_SetItem(hPktInfo, &vitem);

			wsprintf(vitem.pszText, TEXT("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"), parsed_cur->ipv6h.destaddr[0], parsed_cur->ipv6h.destaddr[1],
				parsed_cur->ipv6h.destaddr[2], parsed_cur->ipv6h.destaddr[3], parsed_cur->ipv6h.destaddr[4], parsed_cur->ipv6h.destaddr[5],
				parsed_cur->ipv6h.destaddr[6], parsed_cur->ipv6h.destaddr[7]);
			vitem.iItem = pos;    //行
			vitem.iSubItem = 3; //列
			ListView_SetItem(hPktInfo, &vitem);
		}
		break;
		default:break;
	}
	
	//长度
	wsprintf(vitem.pszText, TEXT("%d"), parsed_cur->len);
	vitem.iItem = pos;    //行
	vitem.iSubItem = 4; //列
	ListView_SetItem(hPktInfo, &vitem);

	//协议
	wsprintf(vitem.pszText, TEXT("%s"), AnsiToUnicode(parsed_cur->pktType));
	vitem.iItem = pos;    //行
	vitem.iSubItem = 5; //列
	ListView_SetItem(hPktInfo, &vitem);

	//mac
	wsprintf(vitem.pszText, TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),parsed_cur->ethh.src[0], parsed_cur->ethh.src[1], parsed_cur->ethh.src[2],
		parsed_cur->ethh.src[3], parsed_cur->ethh.src[4], parsed_cur->ethh.src[5]);
	vitem.iItem = pos;    //行
	vitem.iSubItem = 6; //列
	ListView_SetItem(hPktInfo, &vitem);

	wsprintf(vitem.pszText, TEXT("%02X-%02X-%02X-%02X-%02X-%02X"), parsed_cur->ethh.dest[0], parsed_cur->ethh.dest[1], parsed_cur->ethh.dest[2],
		parsed_cur->ethh.dest[3], parsed_cur->ethh.dest[4], parsed_cur->ethh.dest[5]);
	vitem.iItem = pos;    //行
	vitem.iSubItem = 7; //列
	ListView_SetItem(hPktInfo, &vitem);
	ListView_EnsureVisible(hPktInfo,pos, TRUE);//自动滚屏
	return;
}

void ShowPktCount(HWND hDlg)
{
	char buf[4];
	sprintf(buf, "%d", n_packet->n_arp);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_ARPCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_icmp);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_ICMPCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_ipv4);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_IPV4COUNT), buf);
	sprintf(buf, "%d", n_packet->n_ipv6);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_IPV6COUNT), buf);
	sprintf(buf, "%d", n_packet->n_tcp);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_TCPCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_udp);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_UDPCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_http);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_HTTPCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_https);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_HTTPSCOUNT), buf);
	sprintf(buf, "%d", n_packet->n_total);
	SetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_TOTALCOUNT), buf);
	return;
}

void ShowPktDetail(HWND hDlg)
{
	HWND hPktTree = GetDlgItem(hDlg, IDC_TREE_PACKETHEADER);
	HWND hPktList = GetDlgItem(hDlg, IDC_LIST_PACKET);
	HWND hPktData = GetDlgItem(hDlg, IDC_EDIT_PKTDATA);

	TreeView_DeleteAllItems(hPktTree);//清除原有节点
	LV_ITEM vitem;	//因为包编号没有存储，需要从选中行的listztrl中获取
	DWORD pos;
	TCHAR listbuffer[4];
	TVITEMA tvitem;
	TVINSERTSTRUCTA tvstructure;
	TCHAR treebuffer[30];

	//获取选中行
	pos = SendMessage(hPktList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	vitem.iSubItem = 0;
	vitem.pszText = listbuffer;
	vitem.cchTextMax = 4;
	SendMessage(hPktList, LVM_GETITEMTEXT, pos, (DWORD)&vitem);
	DWORD number = _wtoi(vitem.pszText);
	wsprintf(treebuffer, TEXT("第%d个数据包"), number);

	tvitem.mask = TVIF_TEXT;
	tvitem.cchTextMax = 30;
	tvitem.pszText = (LPSTR)treebuffer;


	//设置tvinsertstructa
	tvstructure.hParent = TVI_ROOT;
	tvstructure.hInsertAfter = TVI_ROOT;
	tvstructure.item = tvitem;

	HTREEITEM root= TreeView_InsertItem(hPktTree, &tvstructure);
	
	//插入链路层解析
	
	wcscpy(treebuffer, TEXT("链路层帧头"));
	tvstructure.hParent = root;
	tvstructure.hInsertAfter = TVI_FIRST;
	HTREEITEM hFrame = TreeView_InsertItem(hPktTree, &tvstructure);

	tvstructure.hParent = hFrame;
	wsprintf(treebuffer, TEXT("源MAC:%02X-%02X-%02X-%02X-%02X-%02X"), parsed_pkts[number].ethh.src[0], 
		parsed_pkts[number].ethh.src[1], parsed_pkts[number].ethh.src[2], parsed_pkts[number].ethh.src[3], 
		parsed_pkts[number].ethh.src[4],parsed_pkts[number].ethh.src[5]);
	TreeView_InsertItem(hPktTree, &tvstructure);

	wsprintf(treebuffer, TEXT("目的MAC:%02X-%02X-%02X-%02X-%02X-%02X"), parsed_pkts[number].ethh.dest[0], 
		parsed_pkts[number].ethh.dest[1], parsed_pkts[number].ethh.dest[2], parsed_pkts[number].ethh.dest[3],
		parsed_pkts[number].ethh.dest[4], parsed_pkts[number].ethh.dest[5]);
	TreeView_InsertItem(hPktTree, &tvstructure);

	wsprintf(treebuffer, TEXT("类型:0x%02x"), parsed_pkts[number].ethh.type);
	TreeView_InsertItem(hPktTree, &tvstructure);

	//插入IP层
	switch (parsed_pkts[number].ethh.type)
	{
		case PROTO_ARP:
		{
			wcscpy(treebuffer, TEXT("ARP包头"));
			tvstructure.hParent = root;
			HTREEITEM hArp = TreeView_InsertItem(hPktTree, &tvstructure);
			tvstructure.hParent = hArp;
			wsprintf(treebuffer, TEXT("硬件类型：%d"), parsed_pkts[number].arph.hrd);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("协议类型：0x%02x"), parsed_pkts[number].arph.protocol);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("硬件地址长度：%d"), parsed_pkts[number].arph.hrdlen);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("协议地址长度：%d"), parsed_pkts[number].arph.prolen);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("操作码：%d"), parsed_pkts[number].arph.opcode);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("发送方MAC：%02X-%02X-%02X-%02X-%02X-%02X"), parsed_pkts[number].arph.srcmac[0], parsed_pkts[number].arph.srcmac[1],
				parsed_pkts[number].arph.srcmac[2], parsed_pkts[number].arph.srcmac[3], parsed_pkts[number].arph.srcmac[4],
				parsed_pkts[number].arph.srcmac[5]);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("发送方IP：%d.%d.%d.%d"), parsed_pkts[number].arph.srcip[0], parsed_pkts[number].arph.srcip[1],
				parsed_pkts[number].arph.srcip[2], parsed_pkts[number].arph.srcip[3]);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("接收方MAC：%02X-%02X-%02X-%02X-%02X-%02X"), parsed_pkts[number].arph.destmac[0], parsed_pkts[number].arph.destmac[1],
				parsed_pkts[number].arph.destmac[2], parsed_pkts[number].arph.destmac[3], parsed_pkts[number].arph.destmac[4],
				parsed_pkts[number].arph.destmac[5]);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("接收方IP：%d.%d.%d.%d"), parsed_pkts[number].arph.destip[0], parsed_pkts[number].arph.destip[1],
				parsed_pkts[number].arph.destip[2], parsed_pkts[number].arph.destip[3]);
			TreeView_InsertItem(hPktTree, &tvstructure);
		}
		break;
		case PROTO_IPV4:
		{
			wcscpy(treebuffer, TEXT("IPV4包头"));
			tvstructure.hParent = root;
			HTREEITEM hIpv4 = TreeView_InsertItem(hPktTree, &tvstructure);
			tvstructure.hParent = hIpv4;
			wsprintf(treebuffer, TEXT("版本：0x%02x"), parsed_pkts[number].ipv4h.version);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("IP头部长度：%d 字节"), parsed_pkts[number].ipv4h.headerlen*4);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("服务类型：%d"), parsed_pkts[number].ipv4h.tos);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("包总长度：%d 字节"), parsed_pkts[number].ipv4h.totallen);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("标识：0x%02x"), parsed_pkts[number].ipv4h.flag);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("分片偏移：%d"), parsed_pkts[number].ipv4h.fragoffset);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("TTL：%d"), parsed_pkts[number].ipv4h.ttl);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("上层协议：0x%02x"), parsed_pkts[number].ipv4h.protocol);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("头部校验和：%d"), parsed_pkts[number].ipv4h.checksum);
			TreeView_InsertItem(hPktTree, &tvstructure);
			struct  in_addr in;
			in.S_un.S_addr = parsed_pkts[number].ipv4h.srcip;
			wsprintf(treebuffer, TEXT("源IP：%s"), AnsiToUnicode(inet_ntoa(in)));
			TreeView_InsertItem(hPktTree, &tvstructure);
			in.S_un.S_addr = parsed_pkts[number].ipv4h.destip;
			wsprintf(treebuffer, TEXT("目的IP：%s"), AnsiToUnicode(inet_ntoa(in)));
			TreeView_InsertItem(hPktTree, &tvstructure);

		}
		break;
		case PROTO_IPV6:
		{
			wcscpy(treebuffer, TEXT("IPV6包头"));
			tvstructure.hParent = root;
			HTREEITEM hIpv6 = TreeView_InsertItem(hPktTree, &tvstructure);
			tvstructure.hParent = hIpv6;
			wsprintf(treebuffer, TEXT("版本：%d"), parsed_pkts[number].ipv6h.version);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("流类型：0x%02x"), parsed_pkts[number].ipv6h.flowtype);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("流标签：%d"), parsed_pkts[number].ipv6h.flowid);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("有效载荷长度：%d 字节"), parsed_pkts[number].ipv6h.payloadlen);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("上层协议：0x%02x"), parsed_pkts[number].ipv6h.nexthead);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("跳限制：%d"), parsed_pkts[number].ipv6h.hoplimit);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("源IP：%02x:%02x:%02x:%02x:%02x:%02x"), parsed_pkts[number].ipv6h.srcaddr[0],
				parsed_pkts[number].ipv6h.srcaddr[1], parsed_pkts[number].ipv6h.srcaddr[2], parsed_pkts[number].ipv6h.srcaddr[3],
				parsed_pkts[number].ipv6h.srcaddr[4], parsed_pkts[number].ipv6h.srcaddr[5]);
			TreeView_InsertItem(hPktTree, &tvstructure);
			wsprintf(treebuffer, TEXT("目的IP：%02x:%02x:%02x:%02x:%02x:%02x"), parsed_pkts[number].ipv6h.destaddr[0],
				parsed_pkts[number].ipv6h.destaddr[1], parsed_pkts[number].ipv6h.destaddr[2], parsed_pkts[number].ipv6h.destaddr[3],
				parsed_pkts[number].ipv6h.destaddr[4], parsed_pkts[number].ipv6h.destaddr[5]);
			TreeView_InsertItem(hPktTree, &tvstructure);
		}
		break;
		default:break;
	}

	//插入icmp数据
	if (parsed_pkts[number].icmph.checksum) {
		wcscpy(treebuffer, TEXT("ICMP包头"));
		tvstructure.hParent = root;
		HTREEITEM hIcmp = TreeView_InsertItem(hPktTree, &tvstructure);

		tvstructure.hParent = hIcmp;
		wsprintf(treebuffer, TEXT("类型：%d"), parsed_pkts[number].icmph.type);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("代码：%d"), parsed_pkts[number].icmph.code);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("序号：%d"), parsed_pkts[number].icmph.seq);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("校验和：%d"), parsed_pkts[number].icmph.checksum);
		TreeView_InsertItem(hPktTree, &tvstructure);
	}
	//插入tcp数据
	else if (parsed_pkts[number].tcph.headlen) {
		wcscpy(treebuffer, TEXT("TCP包头"));
		tvstructure.hParent = root;
		HTREEITEM hTcp = TreeView_InsertItem(hPktTree, &tvstructure);
		tvstructure.hParent = hTcp;

		wsprintf(treebuffer, TEXT("源端口：%d"), parsed_pkts[number].tcph.srcport);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("目的端口：%d"), parsed_pkts[number].tcph.destport);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("序列号：0x%02x"), parsed_pkts[number].tcph.seq);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("确认号：0x%02x"), parsed_pkts[number].tcph.ack);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("头部长度：%d 字节"), parsed_pkts[number].tcph.headlen*4);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wcscpy(treebuffer, TEXT("TCP标志位"));
		HTREEITEM hflag =TreeView_InsertItem(hPktTree, &tvstructure);
		tvstructure.hParent = hflag;
		wsprintf(treebuffer, TEXT("fin：%d"), parsed_pkts[number].tcph.fin);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("syn：%d"), parsed_pkts[number].tcph.syn);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("rst：%d"), parsed_pkts[number].tcph.rst);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("psh：%d"), parsed_pkts[number].tcph.psh);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("ack：%d"), parsed_pkts[number].tcph.ackbit);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("urg：%d"), parsed_pkts[number].tcph.urg);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("ece：%d"), parsed_pkts[number].tcph.ece);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("cwr：%d"), parsed_pkts[number].tcph.cwr);
		TreeView_InsertItem(hPktTree, &tvstructure);
		tvstructure.hParent = hTcp;
		wsprintf(treebuffer, TEXT("窗口大小：%d"), parsed_pkts[number].tcph.winsize);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("校验和：%d"), parsed_pkts[number].tcph.checksum);
		TreeView_InsertItem(hPktTree, &tvstructure);
		if (parsed_pkts[number].tcph.urg) {
			wsprintf(treebuffer, TEXT("紧急指针：0x%02x"), parsed_pkts[number].tcph.urgptr);
			TreeView_InsertItem(hPktTree, &tvstructure);
		}
	}
	//插入udp数据
	else if (parsed_pkts[number].udph.len) {
		wcscpy(treebuffer, TEXT("UDP包头"));
		tvstructure.hParent = root;
		HTREEITEM hUDP = TreeView_InsertItem(hPktTree, &tvstructure);

		tvstructure.hParent = hUDP;
		wsprintf(treebuffer, TEXT("源端口：%d"), parsed_pkts[number].udph.srcport);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("目的端口：%d"), parsed_pkts[number].udph.destport);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("数据包长度：%d 字节"), parsed_pkts[number].udph.len);
		TreeView_InsertItem(hPktTree, &tvstructure);
		wsprintf(treebuffer, TEXT("校验和：%d"), parsed_pkts[number].udph.checksum);
		TreeView_InsertItem(hPktTree, &tvstructure);
	}

	//显示原始数据包信息
	LPSTR data = (LPSTR)malloc(10000);
	if (data == NULL) {
		MessageBox(NULL, _T("分配内存空间失败"), _T("Error"), MB_OK);
		return;
	}
	FormStream(number, data);
	SetWindowTextA(hPktData, data);
	free(data);
	return;
}

void FormStream(__in int number,__out LPSTR data)
{
	u_int dataaddr ;//数据包地址，同wireshark
	int	rowdata;//每一行的数据个数
	u_char asci;//每个字符的asci
	LPSTR cur = data;
	int mov = 0;//游标移动距离
	for (dataaddr = 0; dataaddr < parsed_pkts[number].len; dataaddr += 16)//一行16个字节
	{
		mov = sprintf(cur, "%04x:    ", dataaddr);	
		cur += mov;
		rowdata = (parsed_pkts[number].len - dataaddr) > 16 ? 16 : (parsed_pkts[number].len - dataaddr);
		for (int i = 0; i < rowdata; i++) {
			mov = sprintf(cur, "%02x  ", parsed_pkts[number].rawdata[dataaddr + i]);
			cur += mov;
		}
			
		//不足16，用空格补足
		if (rowdata < 16) {
			for (int i = rowdata; i < 16; i++){
				memcpy(cur, "     ",5);
				cur += 5;
			}
		}
		memcpy(cur, "    ", 4);//空几个空格把二进制和asci分隔开
		cur += 4;
		//显示ascii
		for (int i = 0; i < rowdata; i++)
		{
			asci = parsed_pkts[number].rawdata[dataaddr + i];
			asci = isprint(asci) ? asci : '.';//不可打印就显示.
			mov = sprintf(cur, "%c", asci);
			cur += mov;
		}
		memcpy(cur, "\r\n",2);
		cur += 2;
		if (rowdata < 16)	break;
	}
	memcpy(cur, "\0",1);
	return ;
}