///*
// * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
// * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
// * All rights reserved.
// *
// * Redistribution and use in source and binary forms, with or without
// * modification, are permitted provided that the following conditions
// * are met:
// *
// * 1. Redistributions of source code must retain the above copyright
// * notice, this list of conditions and the following disclaimer.
// * 2. Redistributions in binary form must reproduce the above copyright
// * notice, this list of conditions and the following disclaimer in the
// * documentation and/or other materials provided with the distribution.
// * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
// * nor the names of its contributors may be used to endorse or promote 
// * products derived from this software without specific prior written 
// * permission.
// *
// * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// *
// */

#ifdef _MSC_VER

#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
/*4 bit IP */
typedef struct ip_adress
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_adress;

/* IPv4 头部 */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	u_char	saddr[4];		// Source address
	u_char	daddr[4];		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

//mac 地址
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

//tcp 头部
typedef struct _tcp_header
{
	unsigned short src_port;   //源端口号
	unsigned short dst_port;   //目的端口号
	unsigned int seq_no;    //序列号
	unsigned int ack_no;    //确认号
#if LITTLE_ENDIAN
	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char thl : 4;    //tcp头部长度
	unsigned char flag : 6;    //6位标志
	unsigned char reseverd_2 : 2; //保留6位中的2位
#else
	unsigned char thl : 4;    //tcp头部长度
	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char reseverd_2 : 2; //保留6位中的2位
	unsigned char flag : 6;    //6位标志 
#endif
	unsigned short wnd_size;   //16位窗口大小
	unsigned short chk_sum;   //16位TCP检验和
	unsigned short urgt_p;    //16为紧急指针
}tcp_header;

//包计数
int packet_counter = 0;

int sec=-1;
int min = -1;


//每次捕获到数据包时，libpcap都会自动调用这个回调函数
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	
	struct tm* ltime;
	char timestr[16];
	mac_header* mh;
	ip_header* ih;
	tcp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	//时间
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	//输出包号
	packet_counter++;
	printf("	\nno.%d\n", packet_counter);

	/* print length of the packet */
	//数据包的长度和时间
	//printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);
	mh = (mac_header*)pkt_data;
	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		sizeof(mac_header)); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->src_port);
	dport = ntohs(uh->dst_port);

	

	//	//题目三的输出格式要求
	//	//时间
	printf("%s,", timestr);
	//源MAC
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->src_addr[i]);
	}
	printf("%02X", mh->src_addr[5]);
	printf(",");
	//，源IP，
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->saddr[i]);
	}
	printf("%d,", ih->saddr[3]);
	//目的MAC。
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->dest_addr[i]);
	}
	printf("%02X,", mh->dest_addr[5]);
	//，目的IP。	//长度
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->daddr[i]);
	}
	printf("%d,", ih->daddr[3]);
	for (int i = 0; i < 20; i++)
		printf("%c", (char)pkt_data[66 + i]);
	printf("\n");



	FILE* file = fopen("test.txt", "a+");
	//
	//输出到文件
	//时间
	fprintf(file, "%s,", timestr);
	//源MAC
	for (int i = 0; i < 5; i++) {
		fprintf(file, "%02X-", mh->src_addr[i]);
	}
	fprintf(file, "%02X,", mh->src_addr[5]);
	//，源IP，
	for (int i = 0; i < 3; i++) {
		fprintf(file, "%d.", ih->saddr[i]);
	}
	fprintf(file, "%02X,", ih->saddr[5]);
	//目的MAC。
	for (int i = 0; i < 5; i++) {
		fprintf(file, "%02X-", mh->dest_addr[i]);
	}
	fprintf(file, "%02X,", mh->dest_addr[5]);
	//，目的IP。
	for (int i = 0; i < 3; i++) {
		fprintf(file, "%d.", ih->daddr[i]);
	}
	fprintf(file, "%d", ih->daddr[3]);
	for (int i = 0; i < 20; i++)
		fprintf(file,"%c", (char)pkt_data[66 + i]);
	fprintf(file,"\n");
	//长度
	fclose(file);

}

int main() {

	int i = 0;
	int inum;//网卡
	
	pcap_t* adhandle;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	
	char packet_filter[100] = "tcp";// 存储过滤条件

	u_int netmask; // 子网掩码 
	struct bpf_program fcode;// Structure for "pcap_compile()"
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	//获取端口号
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
	
}
