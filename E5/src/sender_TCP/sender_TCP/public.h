#pragma once
#ifndef PUBLIC_H
#define PUBLIC_H

#include<conio.h>
#include<vector>
#include<iostream>
#include<thread>
#include<winsock2.h>  
#include<stdio.h>
#include<string>
#include<sstream>
#include<ws2tcpip.h>//定义socklen_t
#pragma comment(lib, "WS2_32")  // 链接到WS2_32.lib 
#include <thread>
using namespace std;

#define SERVER_IP "169.254.64.184"// 默认服务器端IP地址
#define SERVER_PORT 8307// 服务器端口号

class client
{
public:
	client();
	int init();
	void process();
	bool isNum(string str);
	vector<string> split(char* str);

private:
	int user;
	int writing;
	sockaddr_in  serverAddr;//IPV4的地址方式包括服务端地址族、服务端IP地址、服务端端口号
	void sendata();
};

#endif
