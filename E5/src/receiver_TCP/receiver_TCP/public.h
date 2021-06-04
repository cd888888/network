#pragma once
#ifndef PUBLIC_H
#define PUBLIC_H

#include<iostream>
#include <winsock2.h>  
#include <stdio.h>
#include <vector>
#include<ws2tcpip.h>//定义socklen_t
#pragma comment(lib, "WS2_32")  // 链接到WS2_32.lib

using namespace std;

#define SERVER_IP "169.254.64.184"// 默认服务器端IP地址
#define SERVER_PORT 8307// 服务器端口号

class server
{
public:
	server();
	void process();
	vector<string> split(char* str);
	int check(string name, string pass);
	


private:
	int listener;//监听套接字
	sockaddr_in  serverAddr;//IPV4的地址方式
	vector <int> socnum;//存放创建的套接字，处理多个客户端的情况

	string username;
	string password;
};


#endif // !PUBLIC_H
