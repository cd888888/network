#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>

#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_INIT    {0}

unsigned short int port = 1080;
int daemon_mode = 0;
int auth_type;
char* arg_username;
char* arg_password;
FILE* log_file;
pthread_mutex_t lock;

//sock端口版本信息
enum socks {
	RESERVED = 0x00,
	VERSION4 = 0x04,
	VERSION5 = 0x05
};

//socks用户名
enum socks_auth_methods {
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

//socks用户密码
enum socks_auth_userpass {
	AUTH_OK = 0x00,
	AUTH_VERSION = 0x01,
	AUTH_FAIL = 0xff
};

//socks指令
enum socks_command {
	CONNECT = 0x01
};

//socks指令类型
enum socks_command_type {
	IP = 0x01,
	DOMAIN = 0x03
};

//代理窗口状态
enum socks_status {
	OK = 0x00,
	FAILED = 0x05
};
//信息输出
void log_message(const char* message, ...)
{
	if (daemon_mode) {
		return;
	}

	char vbuffer[255];
	va_list args;
	va_start(args, message);
	vsnprintf(vbuffer, ARRAY_SIZE(vbuffer), message, args);
	va_end(args);

	time_t now;
	time(&now);
	char* date = ctime(&now);
	date[strlen(date) - 1] = '\0';

	pthread_t self = pthread_self();

	if (errno != 0) {
		pthread_mutex_lock(&lock);
		fprintf(log_file, "[%s][%lu] Critical: %s - %s\n", date, self,
			vbuffer, strerror(errno));
		errno = 0;
		pthread_mutex_unlock(&lock);
	}
	else {
		fprintf(log_file, "[%s][%lu] Info: %s\n", date, self, vbuffer);
	}
	fflush(log_file);
}

//读取报文信息
int readn(int fd, void* buf, int n)
{
	int nread, left = n;
	while (left > 0) {
		//read()会把参数fd 所指的文件传送count 个字节到buf 指针所指的内存中.
		if ((nread = read(fd, buf, left)) == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
		}
		else {
			if (nread == 0) {
				return 0;
			}
			else {
				left -= nread;
				buf += nread;
			}
		}
	}
	return n;
}
//写报文
int writen(int fd, void* buf, int n)
{
	int nwrite, left = n;
	while (left > 0) {
		if ((nwrite = write(fd, buf, left)) == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
		}
		else {
			if (nwrite == n) {
				return 0;
			}
			else {
				left -= nwrite;
				buf += nwrite;
			}
		}
	}
	return n;
}

//关闭当前线程
void app_thread_exit(int ret, int fd)
{
	close(fd);
	pthread_exit((void*)&ret);//返回值使进程运行结果
}

/*
* int connect(int sockfd, struct sockaddr * serv_addr, int addrlen);
* 用来将参数sockfd连接至serv_sddr指定的网络的地址
*/
int app_connect(int type, void* buf, unsigned short int portnum)
{
	int fd;
	struct sockaddr_in remote;
	char address[16];

	memset(address, 0, ARRAY_SIZE(address));

	if (type == IP) {//IP地址绑定
		char* ip = (char*)buf;
		snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
			ip[0], ip[1], ip[2], ip[3]);
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(address);
		remote.sin_port = htons(portnum);

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(fd, (struct sockaddr*)&remote, sizeof(remote)) < 0) {
			log_message("connect() in app_connect");
			close(fd);
			return -1;
		}

		return fd;//返回socket编号
	}
	else if (type == DOMAIN) {//域名信息绑定
		char portaddr[6];
		struct addrinfo* res;
		snprintf(portaddr, ARRAY_SIZE(portaddr), "%d", portnum);
		log_message("getaddrinfo: %s %s", (char*)buf, portaddr);
		int ret = getaddrinfo((char*)buf, portaddr, NULL, &res);
		if (ret == EAI_NODATA) {
			return -1;
		}
		else if (ret == 0) {
			struct addrinfo* r;
			for (r = res; r != NULL; r = r->ai_next) {
				fd = socket(r->ai_family, r->ai_socktype,
					r->ai_protocol);
				if (fd == -1) {
					continue;
				}
				ret = connect(fd, r->ai_addr, r->ai_addrlen);
				if (ret == 0) {
					freeaddrinfo(res);
					return fd;
				}
				else {
					close(fd);
				}
			}
		}
		freeaddrinfo(res);
		return -1;
	}

	return -1;
}

//创建连接，读取版本信息等内容
int socks_invitation(int fd, int* version)
{
	char init[2];
	int nread = readn(fd, (void*)init, ARRAY_SIZE(init));
	if (nread == 2 && init[0] != VERSION5 && init[0] != VERSION4) {
		log_message("They send us %hhX %hhX", init[0], init[1]);
		log_message("Incompatible version!");
		app_thread_exit(0, fd);
	}
	log_message("Initial %hhX %hhX", init[0], init[1]);
	*version = init[0];//版本信息
	return init[1];
}

char* socks5_auth_get_user(int fd)
{
	unsigned char size;
	readn(fd, (void*)&size, sizeof(size));

	char* user = (char*)malloc(sizeof(char) * size + 1);
	readn(fd, (void*)user, (int)size);
	user[size] = 0;

	return user;
}

char* socks5_auth_get_pass(int fd)
{
	unsigned char size;
	readn(fd, (void*)&size, sizeof(size));

	char* pass = (char*)malloc(sizeof(char) * size + 1);
	readn(fd, (void*)pass, (int)size);
	pass[size] = 0;

	return pass;
}

int socks5_auth_userpass(int fd)
{
	char answer[2] = { VERSION5, USERPASS };
	writen(fd, (void*)answer, ARRAY_SIZE(answer));
	char resp;
	readn(fd, (void*)&resp, sizeof(resp));
	log_message("auth %hhX", resp);
	char* username = socks5_auth_get_user(fd);
	char* password = socks5_auth_get_pass(fd);
	log_message("l: %s p: %s", username, password);
	if (strcmp(arg_username, username) == 0
		&& strcmp(arg_password, password) == 0) {
		char answer[2] = { AUTH_VERSION, AUTH_OK };
		writen(fd, (void*)answer, ARRAY_SIZE(answer));
		free(username);
		free(password);
		return 0;
	}
	else {
		char answer[2] = { AUTH_VERSION, AUTH_FAIL };
		writen(fd, (void*)answer, ARRAY_SIZE(answer));
		free(username);
		free(password);
		return 1;
	}
}

int socks5_auth_noauth(int fd)
{
	char answer[2] = { VERSION5, NOAUTH };
	writen(fd, (void*)answer, ARRAY_SIZE(answer));
	return 0;
}

void socks5_auth_notsupported(int fd)
{
	char answer[2] = { VERSION5, NOMETHOD };
	writen(fd, (void*)answer, ARRAY_SIZE(answer));
}

void socks5_auth(int fd, int methods_count)
{
	int supported = 0;
	int num = methods_count;
	for (int i = 0; i < num; i++) {
		char type;
		readn(fd, (void*)&type, 1);
		log_message("Method AUTH %hhX", type);
		if (type == auth_type) {
			supported = 1;
		}
	}
	if (supported == 0) {
		socks5_auth_notsupported(fd);
		app_thread_exit(1, fd);
	}
	int ret = 0;
	switch (auth_type) {
	case NOAUTH:
		ret = socks5_auth_noauth(fd);
		break;
	case USERPASS:
		ret = socks5_auth_userpass(fd);
		break;
	}
	if (ret == 0) {
		return;
	}
	else {
		app_thread_exit(1, fd);
	}
}

int socks5_command(int fd)
{
	char command[4];
	readn(fd, (void*)command, ARRAY_SIZE(command));
	log_message("Command %hhX %hhX %hhX %hhX", command[0], command[1],
		command[2], command[3]);
	return command[3];
}

//读取socks的端口号
unsigned short int socks_read_port(int fd)
{
	unsigned short int p;
	readn(fd, (void*)&p, sizeof(p));
	log_message("Port %hu", ntohs(p));
	return p;
}
//读取socks的IP地址
char* socks_ip_read(int fd)
{
	char* ip = (char*)malloc(sizeof(char) * IPSIZE);
	readn(fd, (void*)ip, IPSIZE);
	log_message("IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
	return ip;
}

void socks5_ip_send_response(int fd, char* ip, unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, IP };
	writen(fd, (void*)response, ARRAY_SIZE(response));
	writen(fd, (void*)ip, IPSIZE);
	writen(fd, (void*)&port, sizeof(port));
}

char* socks5_domain_read(int fd, unsigned char* size)
{
	unsigned char s;
	readn(fd, (void*)&s, sizeof(s));
	char* address = (char*)malloc((sizeof(char) * s) + 1);
	readn(fd, (void*)address, (int)s);
	address[s] = 0;
	log_message("Address %s", address);
	*size = s;
	return address;
}

void socks5_domain_send_response(int fd, char* domain, unsigned char size,
	unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, DOMAIN };
	writen(fd, (void*)response, ARRAY_SIZE(response));
	writen(fd, (void*)&size, sizeof(size));
	writen(fd, (void*)domain, size * sizeof(char));
	writen(fd, (void*)&port, sizeof(port));
}

int socks4_is_4a(char* ip)
{
	return (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0);
}

int socks4_read_nstring(int fd, char* buf, int size)
{
	char sym = 0;
	int nread = 0;
	int i = 0;

	while (i < size) {
		nread = recv(fd, &sym, sizeof(char), 0);

		if (nread <= 0) {
			break;
		}
		else {
			buf[i] = sym;
			i++;
		}

		if (sym == 0) {
			break;
		}
	}

	return i;
}

void socks4_send_response(int fd, int status)
{
	char resp[8] = { 0x00, (char)status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	writen(fd, (void*)resp, ARRAY_SIZE(resp));
}

void app_socket_pipe(int fd0, int fd1)
{
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];
	//对两个socket进行连接
	log_message("Connecting two sockets");

	maxfd = (fd0 > fd1) ? fd0 : fd1;
	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd0, &rd_set);
		FD_SET(fd1, &rd_set);
		/*select函数用于在非阻塞中，当一个套接字或一组套接字有信号时通知你，系统提供select函数来实现多路复用输入/输出模型
		* int select(int maxfd,fd_set *rdset,fd_set *wrset,fd_set *exset,struct timeval *timeout);
		* 1.传入的timeout为NULL，则表示将select()函数置为阻塞状态，直到我们所监视的文件描述符集合中某个文件描述符发生变化是，才会返回结果。
		* 2.传入的timeout为0秒0毫秒，则表示将select()函数置为非阻塞状态，不管文件描述符是否发生变化均立刻返回继续执行。
		* 3.传入的timeout为一个大于0的值，则表示这个值为select()函数的超时时间，在timeout时间内一直阻塞，超过时间即返回结果。
		* 服务端只设置读，不考虑写
		* int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
		* 用于确定一个或多个套接字的状态
		* nfds：表示所要监视的文件描述的范围
		* readfds是指向fd_set结构的指针。这个集合中加入我们所需要监视的文件可读操作的文件描述符
		* writefds:指向fd_set结构的指针，这个集合中加入我们所需要监视的文件可写操作的文件描述符。
		* exceptfds:指向fd_set结构的指针，这个集合中加入我们所需要监视的文件错误异常的文件描述符
		* timeout:指向timeval结构体的指针，通过传入的这个timeout参数来决定select()函数的三种执行方式
		* FD_ZERO(fd_set *fdset) 将指定的文件描述符集清空，在对文件描述符集合进行设置前，必须对其进行初始化，如果不清空，由于在系统分配内存空间后，通常并不作清空处理，所以结果是不可知的。
		* FD_SET(fd_set *fdset) 用于在文件描述符集合中增加一个新的文件描述符。
		* FD_CLR(fd_set *fdset) 用于在文件描述符集合中删除一个文件描述符。
		* FD_ISSET(int fd,fd_set *fdset) 用于测试指定的文件描述符是否在该集合中。

		*/
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);//对maxfd进行度操作

		if (ret < 0 && errno == EINTR) {
			continue;
		}
		//用于测试指定的文件描述符是否在该集合中。
		if (FD_ISSET(fd0, &rd_set)) {
			nread = recv(fd0, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd1, (const void*)buffer_r, nread, 0);
		}
		//用于测试指定的文件描述符是否在该集合中。
		if (FD_ISSET(fd1, &rd_set)) {
			nread = recv(fd1, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd0, (const void*)buffer_r, nread, 0);
		}
	}
}

void* app_thread_process(void* fd)
{
	int net_fd = *(int*)fd;
	int version = 0;
	int inet_fd = -1;
	char methods = socks_invitation(net_fd, &version);

	switch (version) {
	case VERSION5: {//socks5
		socks5_auth(net_fd, methods);
		int command = socks5_command(net_fd);
		//对报文中的信息进行处理
		if (command == IP) {//命令是针对ip的处理
			char* ip = socks_ip_read(net_fd);//读取IP地址
			unsigned short int p = socks_read_port(net_fd);//读取端口号

			inet_fd = app_connect(IP, (void*)ip, ntohs(p));//绑定后的socket编号
			if (inet_fd == -1) {
				app_thread_exit(1, net_fd);//绑定失败，退出进程
			}
			socks5_ip_send_response(net_fd, ip, p);//对客户端发送应答信息
			free(ip);
			break;
		}
		else if (command == DOMAIN) {//命令是对域名的处理
			unsigned char size;
			char* address = socks5_domain_read(net_fd, &size);//读取域名地址
			unsigned short int p = socks_read_port(net_fd);//读取端口号

			inet_fd = app_connect(DOMAIN, (void*)address, ntohs(p));//
			if (inet_fd == -1) {
				app_thread_exit(1, net_fd);//绑定失败，关闭进程
			}
			socks5_domain_send_response(net_fd, address, size, p);//绑定成功，发送应答信息
			free(address);
			break;
		}
		else {
			app_thread_exit(1, net_fd);
		}
	}
	case VERSION4: {//socks4
		if (methods == 1) {
			char ident[255];
			unsigned short int p = socks_read_port(net_fd);//读取端口信息
			char* ip = socks_ip_read(net_fd);//读取ip地址
			socks4_read_nstring(net_fd, ident, sizeof(ident));//读取报文信息

			if (socks4_is_4a(ip)) {
				char domain[255];
				socks4_read_nstring(net_fd, domain, sizeof(domain));
				log_message("Socks4A: ident:%s; domain:%s;", ident, domain);//域名信息
				inet_fd = app_connect(DOMAIN, (void*)domain, ntohs(p));
			}
			else {
				log_message("Socks4: connect by ip & port");
				inet_fd = app_connect(IP, (void*)ip, ntohs(p));
			}

			if (inet_fd != -1) {
				socks4_send_response(net_fd, 0x5a);//连接失败
			}
			else {//连接成功，发送回应消息
				socks4_send_response(net_fd, 0x5b);
				free(ip);
				app_thread_exit(1, net_fd);
			}

			free(ip);
		}
		else {
			log_message("Unsupported mode");
		}
		break;
	}
	}

	app_socket_pipe(inet_fd, net_fd);
	close(inet_fd);
	app_thread_exit(0, net_fd);

	return NULL;
}

int app_loop()
{
	int sock_fd, net_fd;
	int optval = 1;
	struct sockaddr_in local, remote;
	socklen_t remotelen;//socklen_t=int
	/*
	* 返回socket编号
	* int socket(int domain, int type, int protocol);
	* domain:AF_INET表明使用tcp/ip协议模型
	* type:套接字类型stream对应tco协议
	* protrol:协议类型。
	*/
	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_message("socket()");
		exit(1);
	}
	/*
	*int setsockopt(SOCKET s, int level, int optname, const char FAR *optval, int optlen);
	* s:表示一个套接字口的描述
	* level：socket选项的级别 sol_socket:可以在套接字级别上设置选项
	* optnmae:需要设置的选项 so_reuseaddr:允许套接字绑定到已在使用的地址
	* optval:指向存放选项值的缓冲区
	* optval缓冲区的长度
	* 若无错误发生，返回0 否则返回负数
	*/
	if (setsockopt
	(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval,
		sizeof(optval)) < 0) {
		log_message("setsockopt()");
		exit(1);
	}

	//设置套接字
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);//本机的所有IP
	local.sin_port = htons(port);
	/*用来给参数sockfd的socket一个名称
	* int bind(int sockfd, struct sockaddr * my_addr, int addrlen);
	* my_addr指向一sockaddr结构，对于不同的socket domain定义了一个通用的结构体
	*/

	if (bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
		log_message("bind()");
		exit(1);
	}

	//创建一个套接口，并监听申请的连接，允许最大的排队连接队列为25
	if (listen(sock_fd, 25) < 0) {
		log_message("listen()");
		exit(1);
	}

	remotelen = sizeof(remote);
	memset(&remote, 0, sizeof(remote));

	log_message("Listening port %d...", port);

	pthread_t worker;
	while (1) {
		//获取连接
		if ((net_fd =
			accept(sock_fd, (struct sockaddr*)&remote,
				&remotelen)) < 0) {
			log_message("accept()");
			exit(1);
		}
		int one = 1;
		/*设置socket状态
		* int setsockopt(int s, int level, int optname, const void * optval, ,socklen_toptlen);
		* s：需要设置的socket
		* level：指定socket的协议类型
		* optname：选项名称		TCP_NODELAY	不使用Nagle算法　
		* optval:指向存放选项值的缓冲区
		* optvalen缓冲区的长度
		*/
		setsockopt(sock_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
		if (pthread_create//创建一个新的连接进程
		(&worker,//线程标识符
			NULL,//线程属性
			&app_thread_process,//线程函数的起始地址
			(void*)&net_fd//传递给start_routing的参数//传递给线程函数的参数
		) == 0) {//返回0成功
			pthread_detach(worker);//将子进程与主进程分离，分离后资源自动回收
		}
		else {
			log_message("pthread_create()");
		}
	}
}
/// <summary>
/// 守护进程
/// </summary>
void daemonize()
{
	//pid_t=int
	//表示内核中的进程表的索引
	pid_t pid;
	int x;
	/*复制主程序
	* fork()用来复制一份主程序，创建主进程的子进程
	* 返回负值，创建子进程失败
	* 返回零：返回到新创建的子进程
	* 正值，返回父进程或调用者，包含新创建子进程的的ID。
	* 创建多进程
	*/
	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/*
	* 父进程和子进程分开运行，
	* 父进程退出，影响子进程的运行
	* 成功返回进程的会话ID
	* 失败返回-1
	*/
	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	//进程Terminate或Stop的时候，SIGCHLD会发送给它的父进程。缺省情况下该Signal会被忽略
	//忽略该信号。
	signal(SIGCHLD, SIG_IGN);

	//发送给具有Terminal的Controlling Process，当terminal 被disconnect时候发送
	//忽略该信号
	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	//设置建立新文件时的权限遮罩
	umask(0);
	chdir("/");

	for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
		close(x);
	}
}

void usage(char* app)
{
	printf
	("USAGE: %s [-h][-n PORT][-a AUTHTYPE][-u USERNAME][-p PASSWORD][-l LOGFILE]\n",
		app);
	printf("AUTHTYPE: 0 for NOAUTH, 2 for USERPASS\n");
	printf
	("By default: port is 1080, authtype is no auth, logfile is stdout\n");
	exit(1);
}

int main(int argc, char* argv[])
{
	int ret;
	log_file = stdout;
	auth_type = NOAUTH;
	arg_username = "user";
	arg_password = "pass";

	pthread_mutex_init(&lock, NULL);

	/**设置某一信号的对应动作
	//sighandler_t signal(int signum, sighandler_t handler);
	//参数signum：知名所要处理的信号类型，它可以取除了SIGKILL和SIGSTOP外的任何一种信号
	//参数handler：描述与信号关联的动作
	//SIGPIPE：在reader终止之后写pipe的时候发送
	//SIG_IGN：忽略该信号*/
	signal(SIGPIPE, SIG_IGN);

	/*int getopt(int argc, char * const argv[], const char * optstring);
	*argc和argv是由main（）传递的参数个数和内容
	* optstring代表欲处理的选项字符串
	* 此函数会返回在argv中下一个的选项字母，此字母会对应参数optstring中的字母
	* optstring参数后边带了冒号，表示该选项后边必须跟一个参数。该参数赋值给optarg
	*
	*
	* 通过不断地读取指令来进行相关操作
	*/
	while ((ret = getopt(argc, argv, "n:u:p:l:a:hd")) != -1) {//
		switch (ret) {
		case 'd': {//进程守护
			daemon_mode = 1;
			daemonize();
			break;
		}
		case 'n': {//设置监听端口口
			port = atoi(optarg) & 0xffff;
			break;
		}
		case 'u': {//设置用户名
			arg_username = strdup(optarg);//赋值用户名
			break;
		}
		case 'p': {//设置密码
			arg_password = strdup(optarg);//对用户密码赋值
			break;
		}
		case 'l': {//设置输出文件
			freopen(optarg, "wa", log_file);
			break;
		}
		case 'a': {//
			auth_type = atoi(optarg);//赋值用户类型
			break;
		}
		case 'h':
		default://输入错误
			usage(argv[0]);
		}
	}
	log_message("Starting with authtype %X", auth_type);
	if (auth_type != NOAUTH) {
		log_message("Username is %s, password is %s", arg_username,
			arg_password);
	}

	app_loop();//程序开始运行
	return 0;
}

