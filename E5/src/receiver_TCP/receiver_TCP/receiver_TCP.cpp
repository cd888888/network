#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "public.h"


//构造函数，设置服务端信息
server::server()
{
	listener = 0;
	serverAddr.sin_family = PF_INET;//默认服务器的IP地址
	serverAddr.sin_port = SERVER_PORT;//服务器端口号
	serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);//将字符串类型转换uint32_t

password = "cd666";
	username = "cd";
	int   Ret;
	/// WSADATA，一种数据结构。这个结构被用来存储被WSAStartup函数调用后返回的Windows Sockets数据。它包含Winsock.dll执行的数据。
	WSADATA   wsaData;// 用于初始化套接字环境

	//初始化WinSock环境
	//失败时
	if ((Ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		printf("WSAStartup()   failed   with   error   %d\n", Ret);
		WSACleanup();
	}
	/// int socket(int domain,int type,int protocol);
	//domain:该参数一般被设置为AF_INET，表示使用的是IPv4地址。
	//type:该参数也有很多选项，例如SOCK_STREAM表示面向流的传输协议TCP，SOCK_DGRAM表示数据报UDP
	//protocol:协议类型，一般使用默认，设置为0
	//用于打开一个网络通讯接口，
	//出错返回-1
	//成功返回一个socket（文件描述符）
	listener = socket(AF_INET, SOCK_STREAM, 0);//采用ipv4,TCP传输
	if (listener == -1)
	{
		printf("Error at socket(): %ld\n", WSAGetLastError());
		perror("创建失败");
		exit(1);
	}
	cout << "连接创建成功" << endl;

	unsigned long ul = 1;
	//非阻塞设置
	if (ioctlsocket(listener, FIONBIO, (unsigned long*)&ul) == -1)
	{
		perror("ioctl failed");
		exit(1);
	}
	//
	//将固定的网络地址（listener）和端口号（serverAddr）绑定在一起。
	//绑定成功返回0，出错返回1
	if (bind(listener, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
	{
		perror("bind error");
		exit(1);
	}
	//该函数仅被服务器使用
	//listen声明listener处于监听状态，
	//并且允许最多有6个客户端处于连接等待状态
	//成功返回0失败返回-1
	if (listen(listener, 6) == -1)
	{
		perror("listen failed");
		exit(1);
	}
	socnum.push_back(listener);//将监听套接字加入
}


void server::process()
{
	int mount = 0;
	fd_set fds;
	fd_set fds_writer;

	FD_ZERO(&fds);//将fds清零
	FD_ZERO(&fds_writer);



	cout << "正在等待客户端信息......" << endl;
	while (1)
	{
		mount = socnum.size();
		for (int i = 0; i < mount; i++)
		{
			FD_SET(socnum[i], &fds);
		}
		//1.传入的timeout为NULL，则表示将select()函数置为阻塞状态，直到我们所监视的文件描述符集合中某个文件描述符发生变化是，才会返回结果。
		//2.传入的timeout为0秒0毫秒，则表示将select()函数置为非阻塞状态，不管文件描述符是否发生变化均立刻返回继续执行。
		//3.传入的timeout为一个大于0的值，则表示这个值为select()函数的超时时间，在timeout时间内一直阻塞，超过时间即返回结果。
		struct timeval timeout = { 1,0 };//设置每隔1秒select一次

		//服务端只设置读，不考虑写
		//int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
		//用于确定一个或多个套接字的状态
		//nfds：表示所要监视的文件描述的范围
		//readfds是指向fd_set结构的指针。这个集合中加入我们所需要监视的文件可读操作的文件描述符
		//writefds:指向fd_set结构的指针，这个集合中加入我们所需要监视的文件可写操作的文件描述符。
		//exceptfds:指向fd_set结构的指针，这个集合中加入我们所需要监视的文件错误异常的文件描述符
		//timeout:指向timeval结构体的指针，通过传入的这个timeout参数来决定select()函数的三种执行方式
		switch (select(0, &fds, &fds_writer, NULL, &timeout))
		{
			//返回-1：select()函数错误，并将所有描述集合清0
		case -1:
		{
			perror("select\n");
			printf("Error at socket(): %ld\n", WSAGetLastError());
			printf("%d\n", mount);

			Sleep(500);
			break;
		}
		//返回0：表示select()函数超时
		case 0:
		{
			//perror("time out\n");
			break;
		}
		//返回正数值表示已经准备好的描述数符
		default:
		{
			//将数组中的每一个套接字都和剩余的套接字进行比较得到当前的任务
			for (int i = 0; i < mount; i++)
			{
				//如果第一个有套接字可读的消息，就建立建立连接
				if (i == 0 && FD_ISSET(socnum[i], &fds))
				{
					struct sockaddr_in client_address;
					socklen_t client_addrLength = sizeof(struct sockaddr_in);
					//返回一个用户的套接字
					int clientfd = accept(listener, (struct sockaddr*)&client_address, &client_addrLength);
					//添加用户，服务器上显示消息，并通知用户连接成功
					//clientfd:为新接受的从客户端发来的套接字
					socnum.push_back(clientfd);
					cout << "客户端：" << clientfd << " 成功连接本服务器" << endl;
					char ID[1024];
					sprintf(ID, "客户端id为：%d", clientfd);


					//服务器产生ID并发送给客户端让客户端知道自己的ID
					send(clientfd, ID, sizeof(ID) - 1, 0);//减去最后一个'/0'
				}
				//检查集合中的指定文件描述是否完好（可读可写）
				if (i != 0 && FD_ISSET(socnum[i], &fds))
				{
					char buf[1024];
					memset(buf, '\0', sizeof(buf));//初始化
					int size = recv(socnum[i], buf, sizeof(buf) - 1, 0);
					//检测是否断线
					if (size == 0 || size == -1)
					{
						cout << "客户端：" << socnum[i] << "已掉线" << endl;

						closesocket(socnum[i]);//关闭这个套接字
						FD_CLR(socnum[i], &fds);//在列表列表中删除

						socnum.erase(socnum.begin() + i);//在vector数组中删除
						mount--;
					}
					//若没有掉线
					else
					{
						printf("客户端 %d 发来消息: %s \n", socnum[i], buf);
						FD_SET(socnum[i], &fds_writer);
						//提取出用户发来的序列号，用户名，密码；
						vector<string>info = split(buf);

						
						//对用户发来的用户名和密码进行验证
						int res=this->check(info[1], info[2]);
						
						//登录结果返回给客户端
						if (res == 1) {
							info[0] = "true";
						}
						else {
							info[0] = "false";
						}
						cout << info[0].c_str() << endl;
						send(socnum[i], info[0].c_str(), sizeof(info[0].c_str()), 0);
						Sleep(1000);
						FD_ZERO(&fds_writer);

					}
				}
			}
			break;
		}
		}
		//FD_ZERO(&fds);//将fds
	}
}

//将输入的信息根据空格进行分割
vector<string> server::split(char* buf)
{
	vector<string> elems;
	string str = buf;

	int pos = str.find(" ");
	while (pos != -1) {
		elems.push_back(str.substr(0, pos));
		str = str.substr(pos + 1, str.size());
		pos = str.find(" ");
	}
	
	elems.push_back(str);
	return elems;

}

int server::check(string name, string pass)
{
	if (name == username && pass == password)return 1;

	return 0;
}
