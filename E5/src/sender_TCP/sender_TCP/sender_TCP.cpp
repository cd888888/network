#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "public.h"
string SerialNumber;//用户输入的序列号
int stats = 0;//若为0，表示服务器没有崩溃，若为1，表示服务器崩溃

int main()
{
	client user;
	while(1)user.process();

	return 0;
}

//设置客户端信息
client::client()
{
	user = 0;
	writing = 0;
	serverAddr.sin_family = PF_INET;
	serverAddr.sin_port = SERVER_PORT;
	serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);//将字符串类型转换uint32_t
}

//进行初始化,返回0表示初始化成功，返回1表示初始化失败，需要尝试连接服务器
int client::init()
{
	int   Ret;
	WSADATA   wsaData;                        // 用于初始化套接字环境
											  // 初始化WinSock环境
	//使用Socket之前必须调用WSAStartup函数，此函数在应用程序中用来初始化Windows Sockets DLL，
	//只有此函数调用成功后，应用程序才可以调用Windows SocketsDLL中的其他API函数，否则后面的任何函数都将调用失败。

	if ((Ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		cout << "WSAStartup()   failed   with   error" << Ret << endl;
		WSACleanup();
	}

	user = socket(AF_INET, SOCK_STREAM, 0);//采用ipv4,TCP传输
	if (user <= 0)
	{
		cout << "Error at socket():" << WSAGetLastError() << endl;
		exit(1);
	};
	cout << "成功建立连接" << endl;//创建成功
	//阻塞式的等待服务器连接
	if (connect(user, (const sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
	{
		cout << "Error at socket():" << WSAGetLastError() << endl;
		return 1;
	}
	cout << "连接 IP:" << SERVER_IP << " Port:" << SERVER_PORT << " 成功" << endl;//创建成功
	return 0;
}

void client::process()
{
	char recvbuf[1024];
	fd_set fdread, fedwrite;
	FD_ZERO(&fdread);//将fds清零
	FD_ZERO(&fedwrite);//将fds清零

	int flag = 0;
	flag = init();
	if (flag == 1)
	{
		Sleep(5000);
		cout << endl;//5秒后尝试重新连接服务器
		return;
	}//连接服务器失败，需要尝试再次重连

	while (1)
	{
		FD_SET(user, &fdread);
		if (writing == 1) FD_SET(user, &fedwrite);

		struct timeval timeout = { 1,0 };//设置每隔1秒select一次
		switch (select(0, &fdread, &fedwrite, NULL, &timeout))
		{
		case -1:
		{
			cout << "Error at socket():" << WSAGetLastError() << endl;
			break;
		}
		case 0:
		{
			break;
		}
		default:
		{
			//服务端有信息发送回来时，接收消息
			if (FD_ISSET(user, &fdread))
			{
				int size = recv(user, recvbuf, sizeof(recvbuf), 0);
				if (size > 0)
				{
					cout << "服务端回复:" << recvbuf << endl;
					memset(recvbuf, '\0', sizeof(recvbuf));
				}
				else
				{
					cout << "服务端关闭，正在等待服务端开启" << endl;
					Sleep(10000);//等待10秒后尝试重连
					cout << endl;
					cout << "开始尝试重新连接服务器" << endl << endl;
					stats = 1;//表明服务器崩溃了
					return;
				}
				writing = 1;

			}
			if (FD_ISSET(user, &fedwrite))
			{
				FD_ZERO(&fedwrite);//将fedwrite清零
				writing = 1;//设置为写状态
				
			
				sendata();
			}
			break;
		}
		}
	}
}

void client::sendata()
{
	string input;
	vector<string> info;
	cout << "请输入要传送的信息：序列号（10位）+用户名+密码的形式\n";
	getline(cin, input);

	//从用户输入的信息中截取出序列号，用户名和密码
	info.clear();
	info = split((char*)input.c_str());

	//对输入的信息进行校验，无误才向服务端发送信息
	while (1)
	{
		if (info.size() < 3) {

			cout << "序列号的长度应该为10，请重新输入所有信息：" << endl;
			getline(cin, input);
			info.clear();
			info = split((char*)input.c_str());
			continue;
		}
		 if (info.size() == 3)
		{
			SerialNumber = info[0];
			//判断输入序列号是否长为10
			if (SerialNumber.size() != 10)
			{
				cout << "序列号的长度应该为10，请重新输入所有信息：" << endl;
				getline(cin, input);
				info.clear();
				info = split((char*)input.c_str());
				continue;
			}
			//再判断输入的序列号是否全部为数字
			else if (!isNum(SerialNumber))
			{
				cout << "序列号的长度应该为10，请重新输入所有信息：" << endl;
				getline(cin, input);
				info.clear();
				info = split((char*)input.c_str());
				continue;
			}
			else break;
		}
		else break;//如果输入的为两项，表明没有序列号，则不需要进行检验
	}

	//将客户端输入的序列号发送给服务端以求验证
	string str;
	if(info.size()==3)str = info[0] + " " + info[1] + " " + info[2];
	else str = info[0] + " " + info[1];

	send(user, str.c_str(), sizeof(str), 0);//发送消息

	writing = 0;//发送完之后，写状态结束
}

//将输入的信息根据空格进行分割
vector<string> client::split(char *str) 
{
	vector<string> elems;
	const char *delim = " ";
	char *s = strtok(str, delim);
	while (s != NULL) {
		elems.push_back(s);
		s = strtok(NULL, delim);
	}
	return elems;
}

//判断输入的字符串是否全部由数字组成，如果是，返回true，否则返回false
bool client::isNum(string str)
{
     stringstream sin(str);
     double d;
     char c;
     if (!(sin >> d))return false;
     if (sin >> c)return false;
     return true;
 }