
# Unix网络编程
在unix网络编程笔记中，大部分计算机网络的知识将被略过，默认大家有相应的前置基础。

# 第一章 Socket api编程
传统的进程间通信借助内核提供的IPC机制进行, 但是只能限于本机通信, 若要跨机通信, 就必须使用网络通信.( 本质上借助内核-内核提供了socket伪文件的机制实现通信----实际上是使用文件描述符), 这就需要用到内核提供给用户的socket API函数库.

## 1. 网络字节序转换
大端和小端的概念
- 大端字节序:也叫高端字节序(**网络字节序**), 是高端地址存放低位数据, 低端地址存放高位数据
- 小端字节序:也叫低端字节序, 是低地址存放低位数据, 高地址存放高位数据

#include <arpa/inet.h>
- uint16_t htons(uint16_t hostshort);
- uint32_t htonl(uint32_t hostlong);
- uint16_t ntohs(uint16_t netshort);
- uint32_t ntohl(uint32_t netlong);

函数名的**h表示主机host, n表示网络network, s表示short（端口号）, l表示long(IPv4)**

注意：数值型IP地址用htonl。字符串型用inet_pton。

## 2. IP地址转换函数----点分十进制IP转换为网络字节序
#include <arpa/inet.h>
inet_pton：
- 函数说明: 将字符串形式的点分十进制IP转换为大端模式的网络IP(整形4字节数)
- 函数原型：
	- int inet_pton(int af, const char *src, void *dst);
- 参数说明:
	- af: AF_INET、AF_INET6
	- src: 字符串形式的点分十进制的IP地址
	- dst: 传出参数-存放转换后的变量的地址
```cpp
inet_pton(AF_INET,"172.20.10.3",&servaddr.sin_addr.s_addr)
```
inet_ntop：
- 函数说明: 大端形式的网络IP转换为字符串形式的点分十进制的IP
- 函数原型：
	- const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
- 参数说明:
	- af: AF_INET、AF_INET6
	- src: 网络的大端形式的IP地址
	- dst: 转换后的IP地址,一般为字符串数组
	- size: dst的长度
- 返回值: 
	- 成功--返回指向dst的指针
	- 失败--返回NULL, 并设置errno

## 3. 套接字结构体

struct sockaddr结构----通用套接字结构体
```cpp
   struct sockaddr {
        sa_family_t sa_family;
        char     sa_data[14];
   }
```
struct sockaddr_in----IPv4套接字结构体
```cpp
struct sockaddr_in {
         sa_family_t    sin_family; /* address family: AF_INET */
         in_port_t      sin_port;   /* port in network byte order */
         struct in_addr sin_addr;   /* internet address */
   };

   struct in_addr {
         uint32_t  s_addr;     /* address in network byte order */
   };	 //网络字节序IP--大端模式
```
参数介绍：
- sin_family：IPv4，填AF_INET
- sin_port：端口号，网络子节序存储，需要使用htons进行网络字节序的转化
- sin_addr：ip地址，网络子节序存储，又是一个结构体。该地址可以不绑定（或者绑定**INADDR_ANY**，地址全0的宏），系统将默认使用**通配地址**(地址全0)，如果需要绑定，使用htonl或者inet_pton

**通配地址：0.0.0.0**：表示使用本地的任意IP。

**环回地址：127.0.0.1**(mac没办法用)：环回地址是主机用于向自身发送通信的一个特殊地址（也就是一个特殊的目的地址）。

可以这么说：同一台主机上的两项服务若使用环回地址而非分配的主机地址，就可以绕开TCP/IP协议栈的下层。（也就是说：不用再通过什么链路层，物理层，以太网传出去了，而是可以直接在自己的网络层，运输层进行处理了）

IPv4的环回地址为：127.0.0.0到127.255.255.255都是环回地址（只是有两个特殊的保留），此地址中的任何地址都不会出现在网络中


注意：**先用IPv4套接字设置参数，在使用socketAPI的函数时，在利用(struct sockaddr *)转化为通用套接字结构。**

套接字设置的例子：
```cpp
struct sockaddr_in servaddr;
bzero(&servaddr, sizeof(servaddr));
servaddr.sin_family = AF_INET;
servaddr.sin_addr.s_addr = htonl(INADDR_ANY);//INADDR_ANY为宏定义，代表全0的通配地址
servaddr.sin_port = htons(6666);
```
首先将整个结构体清零，然后设置地址类型为AF_INET，网络地址为INADDR_ANY，这个宏表示本地的任意IP地址，因为服务器可能有多个网卡，每个网卡也可能绑定多个IP地址，这样设置可以在所有的IP地址上监听，直到与某个客户端建立了连接时才确定下来到底用哪个IP地址，端口号为6666。
## 4. socketAPI函数介绍
#include <sys/socket.h>
### 4.1 socket函数----创建一个套接字

- **函数作用**：socket()打开一个网络通讯端口，**就像open()一样返回一个文件描述符**，**应用程序可以像读写文件一样用read/write在网络上收发数据**。
- **函数原型**：int socket(int domain, int type, int protocol);
- **函数参数**：
	- domain：IPv4填AF_INET；IPv6填AF_INET6
	- type：TCP填SOCK_STREAM，UDP填SOCK_DGRAM
	- protocol：设0即可
- **返回值**：
	- 成功：像open()一样返回一个文件描述符
	-  失败：返回-1，并设置errno

当调用socket函数以后, **返回一个文件描述符**, **内核会提供与该文件描述符相对应的读和写缓冲区**, 同时还有两个队列, 分别是**请求连接队列**和**已连接队列**.

![在这里插入图片描述](https://img-blog.csdnimg.cn/09eada2f486f4a1a948e013539e03065.png)

### 4.2 bind函数（服务器使用，将IP地址与port和套接字捆绑）
服务器程序所监听的网络地址和端口号通常是**固定不变**的，客户端程序得知服务器程序的地址和端口号后就可以向服务器发起连接，**因此服务器需要调用bind绑定一个固定的网络地址和端口号。**

- **函数作用**：bind()的作用是将参数sockfd和addr绑定在一起，使sockfd这个用于网络通讯的文件描述符监听addr所描述的地址和端口号。前面讲过，struct sockaddr *是一个通用指针类型，addr参数实际上可以接受多种协议的sockaddr结构体，而它们的长度各不相同，所以需要第三个参数addrlen指定结构体的长度
- **函数原型**：int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
- **函数参数**：
	- sockdf：socket文件描述符
	- addr：传入参数，通用套接字结构类型。指定服务器端地址信息，含IP地址和端口号
	- addrlen：传入参数,传入sizeof(addr)大小
- **返回值**：
	- 成功：成功返回0
	- 失败：返回-1,设置errno

### 4.3 listen函数----被动监听请求连接的客户

- 函数原型
	- int listen(int sockfd, int backlog);
- 函数描述: 
	- 将套接字由主动态变为被动态。用于被动监听请求连接的客户
- 参数说明:
	- sockfd: 调用socket函数返回的文件描述符。----监听文件描述符
	- backlog: 同时请求连接的最大个数(还未建立连接) 
- 返回值:
	- 成功: 返回0
	- 失败: 返回-1, 并设置errno

### 4.4 accept函数----获取一个客户端的连接
- 函数原型
	- int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);	
- 函数说明:从已连接队列中获得一个连接, 若**当前没有连接则会阻塞等待.**
- 函数参数:
	- sockfd: 调用socket函数返回的文件描述符
	- addr: 传出参数, 保存客户端的地址信息。如果不需要就传NULL。
	- addrlen: **传入传出参数**,  告诉内核，addr变量所占内存空间大小，内核告诉用户addr变量所占内存空间大小。如果不需要就传NULL。
- 返回值:
	- 成功: 返回一个新的文件描述符----专门用于通信的文件描述符
	- 失败: 返回-1, 并设置errno值.

**accept函数是一个阻塞函数, 若没有新的连接请求, 则一直阻塞.
&emsp;&emsp;从已连接队列中获取一个可用连接, 并获得一个新的文件描述符, 该文件描述符用于和客户端通信.  (内核会负责将请求队列中的连接拿到已连接队列中)**  

注意：调用accept函数不是说新建一个连接，而是从已连接队列中，取出一个可用连接（连接早就完成了）。


### 4.5 connect函数----客户端用于连接服务器
- **函数作用**：**客户端**需要调用connect()连接服务器
- **函数原型**：int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
- **函数参数**：
	-  sockdf：socket文件描述符
	-  addr：传入参数，通用套接字结构类型。指定服务器端地址信息，含IP地址和端口号
	-  addrlen：传入参数,传入sizeof(addr)大小
- **返回值**：
	-  成功：成功返回0
	-  失败：返回-1,设置errno

客户在调用connect前不需要调用bind函数（客户端可以隐式捆绑）。

客户端调用connect函数将激发TCP三次握手的过程。

如果connect失败，则该套接字不能在使用必须close。


### 4.6 数据发送
接下来就可以使用write和read函数进行读写操作了.
除了使用read/write函数以外, 还可以使用recv和send函数

读取数据和发送数据:
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);	
对应recv和send这两个函数flags直接填0就可以了.

注意：利用socket()函数创建套接字后，返回的文件描述符对应的是两个缓冲区（一个读一个写），虽然read/write用的是一个文件描述符，但是写入和读出的缓冲区不是同一个

<font color='red'> 注意: 如果写缓冲区已满, write也会阻塞; read读操作的时候, 若读缓冲区没有数据会引起阻塞. </font>


测试过程中可以使用netstat -anp命令查看监听状态和连接状态
netstat命令: 
a表示显示所有,
n表示显示的时候以数字的方式来显示
p表示显示进程信息(进程名和进程PID)

## 5 socket开发

### 5.1使用socket的API函数编写服务端和客户端程序的步骤

使用socket的API函数编写服务端和客户端程序的步骤图示: 

 ![在这里插入图片描述](https://img-blog.csdnimg.cn/a047b276cb5d4f369d01761732241928.png)

测试过程中可以使用netstat命令查看监听状态和连接状态
- netstat命令: 
	- a表示显示所有,
	- n表示显示的时候以数字的方式来显示
	- p表示显示进程信息(进程名和进程PID)

### 5.2 服务器开发流程
1. 创建socket,返回一个文件描述符listenfd---socket()
	- 该文件描述符用于监听客户端连接
2. 将listenfd和IP、port进行绑定----bind()
3. 将listenfd由主动变为被动监听----listen()
4. 接受一个新的连接,得到一个文件描述符connfd----accept()
	- 该文件描述符是用于和客户端进行通信的
5. 收发数据 
while(1)
  {
  	接收数据---read或者recv
  	发送数据---write或者send
  }
6. 关闭文件描述符----close(listenfd); close(connfd);

### 5.3 客户端开发流程
1. 创建socket,返回一个文件描述符sockfd---socket()
	- 该文件描述符用于与服务器通信
2. 根据设置好的服务器的套接字结构信息 连接服务器----connect()
3. 收发数据 
while(1)
  {
  	接收数据---read或者recv
  	发送数据---write或者send
  }
5. 关闭文件描述符----close(sockfd);

### 5.4 服务器-客户端通信代码案例

需求：客户端连接服务器后，客户端将内容传输到服务器端，服务器输出客户端的内容，并将客户端的内容改成大写并传输回客户端，客户端输出服务器的传输的内容。

**服务器：**
```cpp
//第一章：服务器程序
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "unp.h"

int main()
{
    int listenfd= Socket(AF_INET,SOCK_STREAM,0);
    //初始化套接字
    struct sockaddr_in seraddr;
    bzero(&seraddr, sizeof(seraddr));
    seraddr.sin_family=AF_INET;
    seraddr.sin_port= htons(8888);//随意指定端口号

//    seraddr.sin_addr.s_addr= htonl(INADDR_ANY);
    Bind(listenfd, (struct sockaddr*) &seraddr, sizeof(seraddr));//将套接字和文件描述符绑定
    Listen(listenfd, 128);

    //-----获取客户端的地址信息
    struct sockaddr_in cliaddr;
    socklen_t len= sizeof(cliaddr);//len是值-结果参数
    char IP[16];
    memset(IP,0x00,sizeof(IP));
    //----------

    int connfd= Accept(listenfd, (struct sockaddr *)&cliaddr, &len);//阻塞函数
    printf("IP=[%s], port=[%d]\n", inet_ntop(AF_INET,&cliaddr.sin_addr.s_addr,IP, sizeof(IP)), ntohs(cliaddr.sin_port));//打印客户端的地址

    printf("listenfd=[%d], connfd=[%d]\n", listenfd, connfd);
    int i=0;
    int n=0;
    char buf[1024];
    while(1)
    {
        //先听后发

        memset(buf, 0x00, sizeof(buf));
        //从客户端上读数据
        n=read(connfd, buf, sizeof(buf));//如果缓冲区没有数据就阻塞
        if(n<=0)
        {
            printf("read error or client close, n==[%d] \n", n);
            break;
        }
        printf("server: n = [%d], [%s] \n", n, buf);
        for(i=0;i<n;++i)
        {
            buf[i]= toupper(buf[i]);
        }
        write(connfd, &buf, n);
    }
    close(connfd);
    close(listenfd);
}


```
**客户端：**
```cpp
//第一章：客户端程序
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include <sys/uio.h>
#include <unistd.h>
#include "unp.h"

int main()
{
    //创建socket
    int sockfd=Socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_port= htons(8888);
    inet_pton(AF_INET,"192.168.1.213", &servaddr.sin_addr.s_addr);
    int ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(ret<0)
    {
        perror("connect error");
        return -1;
    }
    char buf[1024];
    int n;
    printf("连接成功，开始通信！\n");
    while(1)
    {
        //读标准输入数据
        memset(buf,0x00, sizeof(buf));
        n = read(STDIN_FILENO,buf,sizeof(buf));
        //发送数据
        write(sockfd, buf, n);

        //接收数据
        memset(buf,0x00, sizeof(buf));
        n = read(sockfd, buf, sizeof(buf));
        if( n <=0)
        {
            printf("read error or server closed, n==[%d] \n", n);
            break;
        }
        printf("client: n = [%d], [%s] \n", n, buf);
    }
    close(sockfd);
    return 0;
}
```



# 第二章 高并发服务器开发(多进程、多线程)
## 1. 包裹（封装）函数
像read、wirte、socket相关函数可以通过封装成Read、Write、Socket来**避免代码的冗余**(前面服务器代码案例已经体现)。

并且有些阻塞函数，**比如read、write、accept在阻塞期间若收到信号，会被信号中断，解除阻塞返回-1，error设置为EINTR**。而这样的错误不应该被看成是错误，**包裹函数也能解决**这样的问题

例如：
```cpp
int Accept(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
	int n;

again:
	if ((n = accept(fd, sa, salenptr)) < 0) {
		if ((errno == ECONNABORTED) || (errno == EINTR))
			goto again;
		else
			perr_exit("accept error");
	}
	return n;
}
```

## 2. 粘包问题及解决方法
粘包：对方连续发送两次数据，读数据时第一次留在缓冲区没有读完，剩余数据在第二次读走了，这时就产生粘包

解决办法：包头+数据
具体来说就是发送数据时在数据的前面加上这次数据的长度。例如：假设四个字节表示数据长度：四个字节长度+数据部分。
对方在接收后，先接收到包头，就知道这次应该读多少个字节的数据。

## 3. 多进程服务器的开发
多进程：
- **父进程**负责监听接收新的连接，并回收连接结束的子进程资源
- **子进程**负责处理与客户端通信（接收和发送数据）

### 3.1 多进程服务器的开发流程
处理流程:
```
1 创建socket, 得到一个监听的文件描述符lfd---socket()
2 将lfd和IP和端口port进行绑定-----bind();
3 设置监听----listen()
4 进入while(1)
  {
  	//等待有新的客户端连接到来
  	cfd = accept();
  	
  	//fork一个子进程, 让子进程去处理数据
  	pid = fork();
  	if(pid<0)
  	{
  		exit(-1);
  	}
  	else if(pid>0)
  	{
  		//关闭通信文件描述符cfd
  		close(cfd);
  	}
  	else if(pid==0)
  	{
  		//关闭监听文件描述符
  		close(lfd);
  		
  		//收发数据
  		while(1)
  		{
  			//读数据
  			n = read(cfd, buf, sizeof(buf));
  			if(n<=0)
  			{
  				break;
  			}
  			
  			//发送数据给对方
  			write(cfd, buf, n);
  		}
  		
  		close(cfd);
  		
  		//下面的exit必须有, 防止子进程再去创建子进程
  		exit(0);
  	}
  }
  close(lfd);
```
还需要添加的功能: 父进程使用SIGCHLD信号完成对子进程的回收

注意: 使用Accpet避免阻塞函数被信号打断。

###  3.2 多进程服务器的相关代码
需求：
- 父进程 负责监听接收新的连接，并回收连接结束的子进程资源。
- 子进程 负责处理新的连接（接收和发送数据）
```cpp
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "unp.h"

//信号处理函数
void sighandler(int signum)
{
    pid_t pid;
    while(1)
    {
        pid = waitpid(-1, NULL, WNOHANG);
        if(pid>0)
        {
            printf("已利用信号SIGCHLD回收子进程资源,pid=[%d]\n", pid);
        }
        if(pid ==-1 || pid ==0)
            break;
    }
}

int main()
{
    int listenfd = Socket(AF_INET, SOCK_STREAM,0);

    //绑定
    struct sockaddr_in seraddr;
    seraddr.sin_family=AF_INET;
    seraddr.sin_port= htons(8888);
    inet_pton(AF_INET,"192.168.1.213",&seraddr.sin_addr.s_addr);
    Bind(listenfd,(struct sockaddr*)&seraddr, sizeof(seraddr));
    //设置监听
    Listen(listenfd,128);

    pid_t pid;
    int connfd;
    struct sockaddr_in cliaddr;
    socklen_t len;
    char sIP[16];
    while (1)
    {
        //注册信号捕捉函数
        signal(SIGCHLD,sighandler);
        //接收新的连接
        len= sizeof(cliaddr);
        memset(sIP,0x00, sizeof(sIP));
        connfd = Accept(listenfd, (struct sockaddr*)& cliaddr, &len);
        printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET,&cliaddr.sin_addr.s_addr,sIP, sizeof(sIP)), ntohs(cliaddr.sin_port));
        //创建子进程，让子进程完成通信
        pid = fork();
        if(pid < 0)
        {
            perror("fork error");
            exit(-1);
        }

        if(pid>0)//父进程
        {
            close(connfd);
        }

        if(pid == 0)//子进程
        {
            close(listenfd);
            int n,i;
            char buf[1024];
            while(1)//子进程通信
            {
                memset(buf,0x00, sizeof(buf));
                n = Read(connfd, buf, sizeof(buf));
                if(n<=1)
                {
                    printf("read error or client close\n");
                    break;
                }
                printf("client[%d]---->buf=%s \n", ntohs(cliaddr.sin_port),buf);
                for(i=0;i<n;++i)
                {
                    buf[i]= toupper(buf[i]);
                }
                Write(connfd, buf, n);
            }
            //通信完关闭连接的描述符，并结束子进程
            close(connfd);
            exit(0);
        }
    }
    close(listenfd);
    return 0;
}
```

## 4. 多线程服务器的开发
多线程：
- **父线程**负责监听接收新的连接
- **子线程**负责处理与客户端通信（接收和发送数据）

注意：使用多线程要将子线程设置为分离属性, 让线程在退出之后自己回收资源.

多进程和多线程的服务器开发的区别：
&emsp;&emsp;多进程是复制了文件描述符，而多线程是共享同一个文件描述符，而不是复制的，不能随便关闭，如果关闭了会造成主线程出错。
### 4.1 多线程服务器的开发流程
多线程和多进程的开发基本逻辑差不多。但是有一个细节要注意：

**多线程版不能和多进程版一样只使用一个用于通信的文件描述符connfd。**
原因是：主线程在一个时间片内可能会有多个客户端进行连接，导致最后在每个线程的回调函数中获取的都是最后一个线程连接的connfd。(这个问题在《linux系统编程》--《循环创建多个子线程》中讨论过)

解决办法：是通过数组来存储每个线程连接的connfd。并且是结构体数组，结构体内可以存：1. 每次连接对应的线程id 2. connfd 3. 以及对应的客户端的地址。

并且结构体中的connfd可以初始化为-1，这样可以循环使用这个数组。（每次要找一个位置存新的连接的时候就for循环找connfd=-1的位置进行存储）

### 4.2 多线程服务器的相关代码

```cpp
//第二章：多线程服务器的代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "unp.h"
#include <pthread.h>

//-------------结构体数组相关-------------
//创建结构体数组来存用于通信的文件描述符connfd
typedef struct Pthread_Struct
{
    pthread_t pthreadID;
    int connfd;//若为-1表示可用, 大于0表示已被占用
    struct sockaddr_in cliaddr;
}Pthread_Struct;

int pthread_number=3;//允许最大连接的客户数
struct Pthread_Struct pthread_struct[3];
//初始化结构体数组
void Pthread_Struct_init(Pthread_Struct * pthread_struct)
{
    int i=0;
    for(i = 0;i<pthread_number;++i)
    {
        pthread_struct[i].connfd = -1;
    }
}
//查找结构体数组空闲的索引
int find_index(Pthread_Struct * pthread_struct)
{
    int i = 0;
    for(i = 0;i < pthread_number; i++)
    {
        if(pthread_struct[i].connfd==-1)
            break;
    }
    return i;
}
//-----------------------------------

void * pthread_work(void * arg)
{
    struct Pthread_Struct * pthread_ = (struct Pthread_Struct *)arg;
    int connfd = pthread_->connfd;

    //开始通信
    int n;
    int i;
    char buf[1024];
    while (1)
    {
        memset(buf,0x00,sizeof(buf));
        //从客户端接收信息
        n = Read(connfd, buf, sizeof(buf));
        if(n<=1)
        {
            printf("子线程连接结束---->prot=[%d]\n", ntohs(pthread_->cliaddr.sin_port));
            close(connfd);
            pthread_->connfd=-1;//设置-1表示该位置可用
            pthread_exit(NULL);
        }
        printf("client[%d]---->buf=%s", ntohs(pthread_->cliaddr.sin_port), buf);
        for(i=0;i<n;++i)
        {
            buf[i]= toupper(buf[i]);
        }
        //发送给客户端
        Write(connfd, buf, n);
    }

}

int main()
{
    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    //设置端口复用
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    //绑定
    struct sockaddr_in seraddr;
    seraddr.sin_family=AF_INET;
    seraddr.sin_port= htons(8888);
    inet_pton(AF_INET, "192.168.1.213",&seraddr.sin_addr.s_addr);
    Bind(listenfd, (struct sockaddr *)&seraddr, sizeof(seraddr));
    //监听
    printf("开始监听！\n");
    Listen(listenfd, 128);

    //初始化数组
    Pthread_Struct_init(pthread_struct);

    int connfd;
    socklen_t len;
    struct sockaddr_in cliaddr;
    char sIP[16];//用于显示客户端ip地址
    int i;//结构体数组的索引
    while(1)
    {
        //接收新的连接
        len= sizeof(cliaddr);
        memset(sIP,0x00, sizeof(sIP));
        connfd = Accept(listenfd, (struct sockaddr*)& cliaddr, &len);

        //用结构体数组接收connfd和地址结构
        i= find_index(pthread_struct);
        //判断是否结构体数组是否还有空间存放
        if(i==pthread_number)
        {
            printf("可连接的数量已满，拒绝连接访问\n");
            close(connfd);
            continue;//跳过本次while循环
        }
        //对空闲位置的元素的成员赋值
        pthread_struct[i].connfd=connfd;
        pthread_struct[i].cliaddr=cliaddr;

        printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET,&cliaddr.sin_addr.s_addr,sIP, sizeof(sIP)), ntohs(cliaddr.sin_port));
        //创造子线程进行通信
        pthread_create(&(pthread_struct[i].pthreadID), NULL, pthread_work, &(pthread_struct[i]));
        //设置子线程为分离属性
        pthread_detach(pthread_struct[i].pthreadID);

    }
    close(listenfd);
    return 0;
}
```

# 第三章 状态图转换-心跳包-select
## 1.状态转换图

![在这里插入图片描述](https://img-blog.csdnimg.cn/c4de746d019c4fc6a536f3c0be7eb379.png)
四次挥手过程:
- 客户端: SYN_SENT ESTABLISHED
- 服务器: LISTEN SYN_RCVD ESTABLISHED

从图中可知，在三次握手时候，当C/S处在ESTABLISHED时，说明可以通信了

四次挥手过程:
- 主动关闭方: FIN_WAIT_T  FIN_WAIT_2 **TIME_WAIT**
- 被动关闭方: CLOSE_WAIT  LAST_ACK

最后的TIME_WAIT位置不太对，应该在客户端发完ack后，开始TIME_WAIT。

![在这里插入图片描述](https://img-blog.csdnimg.cn/8524b3bf641b4b5eaedb06cb8bdfec89.png)

## 2. 为什么TIME_WAIT要2MSL
什么时候代码会出现：bind error: Address already in use
&emsp;&emsp;这个错误其实就是服务器处在TIME_WAIT状态，由于服务器主动先关闭引起的。

为什么需要2MSL?
1. **预防客户端最后ACK发送失败**：这样服务器会在2MSL内重发最后的FIN
2. **预防先前发送的已经重传过的旧分组（在路由中迷路，但是最后找到了目的地，只是路途花的时间长）重新发送到 新的相同的IP地址和端口之间的TCP连接**：说的有点绕口，具体来说就是比如有个分组，在一段时间内接收方没收到，那么发送方会默认丢包并重传。随后，发送方与接收方断开连接又重新开始新的连接（IP和端口号均未变），如果此时那个旧的分组又最终送到了目的地，那么可能会引起程序异常。所以许多操作系统为了避免问题2，采取的解决办法是只要端口被占用（2MSL期间），服务就不能启动。

## 3. 端口复用----解决bind error
解决服务器主动关闭导致bind error: Address already in use。原因上一节已经说过。
```cpp
int opt = 1;
setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
 ```

## 4. 半关闭
如果客户端close, 而服务器没有close, 则认为客户端是半关闭状态, 处于半关闭状态的时候, 可以接收数据, 但是不能发送数据. 相当于把**文件描述符**的**写缓冲区操作关闭**了.
&emsp;&emsp;注意: 半关闭一定是出现在主动关闭的一方.

### 4.1 shutdown----实现半关闭

- **函数描述**: shoutdown 可以实现关闭读端或者写端
- **函数原型**: int shutdown(int sockfd, int how)
- **函数参数**
	- sockfd：监听套接字
	- how：
		- SHUT_RD：关闭读端
		- SHUT_WR：关闭写端
		- SHUT_RDWR：关闭读写端

shutdown和close的区别:
- shutdown可以实现半关闭, close不行
- shutdown关闭的时候, 不考虑文件描述符的引用计数, 是直接关闭。close考虑文件描述符的引用计数, 调用一次close只是将引用计数减1,  只有减小到0的时候才会真正关闭.


## 5. 心跳包
长连接和短连接的概念:
- 长连接: 连接建立好之后,一直保持连接不关闭
- 短连接: 连接收发数据完毕之后就立刻关闭.

心跳包的作用：用于检查长连接是否正常的字符串。

**心跳包一般用于长连接。**

如何使用心跳包：
- 在启动程序中自己**定义心跳包**，使用灵活，能实时把控。
- 使用函数setsockopt（不常用）

举个例子：
&emsp;&emsp;服务A给日发送心跳数据AAAA，服务B收到AAAA之后，给A回复BBBB，此时A收到BBBB之后，认为连接正常;
&emsp;&emsp;假如A连续发送了多次(如3-5次)之后，仍然没
有收到B的回复，则判断连接异常;异常之后，A应该重新连接

**那么如何让心跳数据和正常的业务数据不混淆**？
解決力法：
- 双方可以协商协议． 如利用包头+数据：4个字节长度＋具体数据
- 如果发送心跳数据应该：0004AAAA
- 如果发送业务数据：00101234567890

B若收数据的时候先收4个字节的报头数据，然后计算长度，若计算长度为4，且数据为AAAA, 则认为是心跳数据（协议内容自己协商），则B服务会组织应答数据给A：0004BBBB

## 6. select函数----高并发服务器模型
在之前的服务器开发版本中，如果不使用多进程/多线程，但是想让服务器支持多个客户端连接是做不到的，原因是accpet和read/write都是阻塞函数，在等read的时候没办法accept，在等accept时候没办法read。

select就是用于在一个进程里处理多个客户端连接情况。

多路IO复用技术: 一旦内核发现指定的一个或者多个I/O条件就绪，就通知进程

&emsp;&emsp; **select**：同时监听多个文件描述符, 将监控的操作交给内核去处理。调用select函数其实就是委托内核帮我们去检测哪些文件描述符有可读数据,可写,异常发生; 
用了该函数以后，程序**就不用阻塞等待了**，由内核监控，当有数据来的时候，内核会告诉，直接去读就行了。

数据类型 **fd_set**: 文件描述符集合--本质是位图(和信号集sigset_t一样)

select:
- **函数原型：** 
&emsp;&emsp;int select(int nfds, fd_set * readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
- **函数介绍**: 委托内核监控该文件描述符对应的读,写或者异常事件的发生。
- **参数说明:** 
	- nfds: 最大的文件描述符+1
	- readfds: 读文件描述符集合, 是一个**传入传出参数**
		- 传入: 指的是告诉内核哪些文件描述符需要监控
		- 传出: 指的是内核告诉应用程序哪些文件描述符发生了变化：发生变化置1.
	- writefds: 写文件描述符集合(**传入传出参数**)
	- execptfds: 异常文件描述符集合(**传入传出参数**)
	- timeout: 
		- NULL：表示永久阻塞, 直到有事件发生
		- 0 ：表示不阻塞, 立刻返回, 不管是否有监控的事件发生
		- \>0：表示阻塞的时长，若没有超过时长，则一直阻塞；若在时间内，有事件发生，则立即返回；若超过时长则立刻返回。
	
- **返回值**: 
	- 成功：返回发生变化的文件描述符的个数
	- 失败：返回-1, 并设置errno值.

```cpp
nready = select(maxfd+1, &readfds, NULL, NULL, NULL);
```
提供了几个宏来帮助判断具体哪个文件描述符发生了变化：

- void FD_CLR(int fd, fd_set *set);
	- 将fd从set集合中清除.
- int FD_ISSET(int fd, fd_set *set);
	- 功能描述: 判断fd是否在集合中
	- 返回值: 如果fd在set集合中, 返回1, 否则返回0.
- void FD_SET(int fd, fd_set *set);
	- 将fd设置到set集合中.
- void FD_ZERO(fd_set *set);
	- 初始化set集合.

## 7. 利用select开发高并发服务器
### 7.1 select开发服务器流程
在用select开发服务器中，主要用select干两件事：
- 监听客户端的connect
- 监听客户端的发送的数据  

使用select的开发服务端流程:
```cpp
1 创建socket, 得到监听文件描述符lfd---socket()
2 设置端口复用-----setsockopt()
3 将lfd和IP  PORT绑定----bind()
4 设置监听---listen()
5 fd_set readfds;  //定义文件描述符集变量
  fd_set tmpfds;//内核返回的集合变量，只有这个集合我们才知道哪些文件描述符发生了变化
  FD_ZERO(&readfds);  //清空文件描述符集变量
  FD_ZERO(&tmpfds);
  FD_SET(lfd, &readfds);//将lfd加入到readfds集合中;
  maxfd = lfd;
  while(1)
  {
  	tmpfds = readfds;
  	nready = select(maxfd+1, &tmpfds, NULL, NULL, NULL);
  	if(nready<0)
  	{
  		if(errno==EINTR)//被信号中断
  		{
  			continue;
  		}
  		break;
  	}
  	
 	//有客户端连接请求到来
 	if(FD_ISSET(lfd, &tmpfds))
 	{
 		//接受新的客户端连接请求，此时accept一定不会阻塞
 		cfd = accept(lfd, NULL, NULL);
 		
 		//将cfd加入到readfds集合中
 		FD_SET(cfd, &readfds);
 		
 		//修改内核监控的文件描述符的范围
 		if(maxfd<cfd)
 		{
 			maxfd = cfd;
 		}
 		
 		if(--nready==0)
 		{
 			continue;
 		}
 	}
 	
 	
 	//有客户端数据发来
 	for(i=lfd+1; i<=maxfd; i++)
 	{
 		if(FD_ISSET(i, &tmpfds))
 		{
		//read数据,此时read一定不会阻塞
 			n = read(i, buf, sizeof(buf));
 			if(n<=0)
 			{
 				close(i);
 				//将文件描述符i从内核中去除
 				FD_CLR(i, &readfds);
 				continue;
 			}
 			
 			//write应答数据给客户端
 			write(i, buf, n);
 			if(--nready==0)
 			{
 				break;
 			}
 		}
 	}
 	
 	close(lfd);
 	
 	return 0;
 }
 ```
### 7.2 select开发服务器的相关代码
需求：利用单进程和select完成多个客户端的连接。注意：在用select开发服务器中，主要用select干两件事：
- 监听客户端的connect
- 监听客户端的发送的数据  
```cpp
//第三章：select开发服务器代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "unp.h"
#include <pthread.h>

int main()
{
    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);

    //端口复用
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    //绑定
    struct sockaddr_in servaddr;
    servaddr.sin_family=AF_INET;
    servaddr.sin_port= htons(8888);
    inet_pton(AF_INET,"192.168.1.213", &servaddr.sin_addr.s_addr);
    Bind(listenfd,(struct sockaddr *)&servaddr, sizeof(servaddr));
    //监听
    Listen(listenfd,128);
    printf("listening....\n");
    int connfd;
    fd_set readfds;//定义文件描述符集变量
    fd_set tmpfds;//内核返回的集合变量，只有这个集合我们才知道哪些文件描述符发生了变化
    FD_ZERO(&readfds);//初始化
    FD_ZERO(&tmpfds);
    FD_SET(listenfd, &readfds);//将listenfd加入到readfds中，委托内核监控
    int maxfd=listenfd;
    int nready;//接收select返回的值

    //发送数据相关
    char buf[1024];
    int n;
    //获取客户端信息相关
    struct sockaddr_in cliaddr;
	socklen_t len = sizeof(cliaddr);
    char sIP[16];
    while(1)
    {
        tmpfds=readfds;
        //temfds用于函数的输入输出参数：
        //输入：告诉内核要帮我们监控哪些文件描述符
        //输出：内核告诉我们哪些文件描述符发生变化

        //设置内核监控文件描述符，除非有事件发送，否则永久阻塞
        nready = select(maxfd+1, &tmpfds,NULL,NULL,NULL);
        if(nready<0)
        {
            if(errno==EINTR)//被信号打断
                continue;
            break;
        }
        //两种会取消阻塞：1、listenfd 2、connfd

        //1、有客户端连接请求到来
        if(FD_ISSET(listenfd,&tmpfds))
        {
            //接受新的客户端连接请求，此时accept一定不会阻塞
            connfd = Accept(listenfd, (struct sockaddr*)&cliaddr, &len);
            printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET,&cliaddr.sin_addr.s_addr,sIP, sizeof(sIP)), ntohs(cliaddr.sin_port));
            //把新连接的文件描述符加入到readfds集合中
            FD_SET(connfd, &readfds);

            //修改内核监控的文件描述符的范围
            if(maxfd<connfd)
                maxfd=connfd;

            --nready;
            if(nready==0)//如果只有一个客户端连接请求
                continue;
        }
        //2、有客户端数据发来
        for(connfd=listenfd+1;connfd<=maxfd;++connfd)
        {
            //判断哪个客户端发送数据
            if(FD_ISSET(connfd, &tmpfds))
            {
                memset(buf,0x00, sizeof(buf));
                //read数据,此时read一定不会阻塞
                n = Read(connfd,buf, sizeof(buf));
                if(n<=1)//客户端断开连接
                {
                    //关闭连接
                    close(connfd);
                    //将文件描述符connfd从内核中去除
                    FD_CLR(connfd, &readfds);
                    printf("read error or client close\n");
                    continue;
                }
                printf("客户端发送数据：%s \n",buf);
                int i=0;
                for(i=0;i<n;++i)
                {
                    buf[i]= toupper(buf[i]);
                }
                //write应答数据给客户端
                Write(connfd, buf, n);
                --nready;
                if(nready==0)
                    break;
            }
        }
    }
    close(listenfd);
    return 0;
}
```

### 7.3 简单优化7.2节的代码
7.2节的代码存在一点小瑕疵：
&emsp;&emsp;如果有效的文件描述符比较少（比如一开始连接了100个客户，最后只剩下一个还连接），会使得循环次数太多。

解决办法：
&emsp;&emsp;把有效的文件描述符放到数组中，并记录最大元素的下标索引。具体代码的修改移步到：https://github.com/jiong1998/unix_socket.io/issues/5


### 7.4 select优缺点
- select优点:
	- 一个进程可以支持多个客户端
	- select支持跨平台
- select缺点:
	- 代码编写困难
	- 会涉及到用户区到内核区的来回拷贝
	- 当客户端多个连接, 但少数活跃的情况, select效率较低
例如: 作为极端的一种情况, 3-1023文件描述符全部打开, 但是只有1023有发送数据, select就显得效率低下
	- 最大支持1024个客户端连接
select最大支持1024个客户端连接不是有文件描述符表最多可以支持1024个文件描述符限制的, 而是由FD_SETSIZE=1024限制的,修改该值需要修改、编译内核，一般不建议这么做。

# 第四章 poll-epoll
poll实际开发用的少。linux下可以用epoll，unix下用不了epoll

## 1. 多路IO-poll
### 1.1 poll函数---监控多路IO
#include <poll.h>

poll的效率处在select与epoll之间。和select类似。
```cpp
struct pollfd 
{
   int   fd;// 监控的文件描述符
   short events;//输入参数, 表示告诉内核要监控的事件, 读事件, 写事件, 异常事件  
   short revents;//输出参数, 表示内核告诉应用程序有哪些文件描述符有事件发生
};
```

- **函数原型：**
	- int poll(struct pollfd *fds, nfds_t nfds, int timeout);
- **函数说明**: 跟select类似, 监控多路IO, 但poll不能跨平台.
- **参数说明**:
	- fds: 传入传出参数, 实际上是一个结构体数组
		- fds.fd: 要监控的文件描述符，如果fd=-1，表示内核不监控该fd。
		- fds.events: 输入参数，告诉内核要监控的事件
			- POLLIN---->读事件
			- POLLOUT---->写事件
		- fds.revents: 输出参数，内核返回发生变化的事件
	- nfds: 告诉内核监控的范围，具体是数组下标的最大值+1
	- timeout: 超时时间, 单位是毫秒.
		- -1:永久阻塞, 直到监控的事件发生
		- 0: 不管是否有事件发生, 立刻返回
		- \>0: 直到监控的事件发生或者超时
- **返回值:** 
	- \>0, 发生变化的文件描述符的个数
	- =0, 没有文件描述符发生变化
	- -1, 发生错误, 并设置errno值.

若timeout=0, poll函数不阻塞,且没有事件发生, 此时返回-1, 并且errno=EAGAIN, 这种情况不应视为错误.

EAGAIN：如果你连续做read（read的文件描述符已经设置为非阻塞情况）操作而没有数据可读。此时程序不会阻塞起来等待数据准备就绪返回，read函数会返回一个错误EAGAIN，提示你的应用程序现在没有数据可读请稍后再试。

poll总结：
1. 当poll函数返回的时候, 结构体当中的fd和events没有发生变化, **究竟有没有事件发生由revents来判断**, 所以poll是请求和返回分离.
2. struct pollfd结构体中的fd成员若赋值为-1, 则poll不会监控.
3. 相对于select, poll没有本质上的改变; 但是poll可以突破1024的限制.
### 1.2 利用poll开发高并发服务器
整体逻辑和select开发服务器差不多。

需求：利用单进程和poll完成多个客户端的连接。注意：在用poll开发服务器中，主要用poll干两件事：
- 监听客户端的connect
- 监听客户端的发送的数据  
```cpp
//第四章：poll开发服务器代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "unp.h"
#include <poll.h>

int main()
{
    int listenfd = Socket(AF_INET,SOCK_STREAM,0);

    //允许端口复用
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    //绑定
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    inet_pton(AF_INET, "192.168.1.213", &servaddr.sin_addr.s_addr);
    Bind(listenfd,(struct sockaddr*)&servaddr, sizeof(servaddr));

    //监听
    Listen(listenfd,128);
    printf("listening....\n");

    int i;
    int nready;
    int maxi=0;//maxi表示内核监控的范围
    int connfd;
    struct pollfd client[1024];

    //将监听文件描述符委托给内核监控----监控读事件
    client[0].fd=listenfd;
    client[0].events=POLLIN;

    //初始化结构体
    for(i=1;i<1024;++i)
        client[i].fd=-1;

    //接发数据相关
    int n;
    char buf[1024];
    //获取客户端信息相关
    struct sockaddr_in cliaddr;
    char sIP[16];
    socklen_t len = sizeof(cliaddr);

    while (1)
    {
        nready = poll(client, maxi+1, -1);
        //异常情况
        if(nready<0)
        {
            if(errno == EINTR)//被信号打断
                continue;
            break;
        }
        //两种会取消阻塞：1、listenfd 2、connfd

        //1、有客户端连接请求到来
        if(client[0].revents == POLLIN)
        {
            connfd = Accept(listenfd,(struct sockaddr*)&cliaddr, &len);
            //找位置放新的连接
            for(i=1;i<1024;++i)
            {
                if(client[i].fd==-1)
                {
                    client[i].fd=connfd;
                    client[i].events=POLLIN;
                    printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET, &cliaddr.sin_addr.s_addr, sIP,sizeof(sIP)), ntohs(cliaddr.sin_port));
                    break;
                }
            }

            //若没有可用位置, 则关闭连接
            if(i == 1024)
            {
                close(connfd);
                printf("客户端连接数达到最大值\n");
                continue;
            }

            //修改client数组下标最大值
            if(i>maxi)
                maxi=i;

            if(--nready==0)
                continue;
        }
        //2、有客户端数据发来
        int k;
        for(k=1;k<=maxi;++k)
        {
            if(client[k].fd==-1)
                continue;
            if(client[k].revents == POLLIN)
            {
                connfd = client[k].fd;
                memset(buf, 0x00, sizeof(buf));
                n = Read(connfd, buf, sizeof(buf));
                if(n<=1)
                {
                    close(connfd);
                    //将文件描述符connfd从内核中去除
                    client[k].fd = -1;
                    printf("read error or client close\n");
                    continue;
                }
                printf("客户发送数据：%s\n", buf);
                //改成大写输出
                for (i = 0; i < n; ++i)
                {
                    buf[i]= toupper(buf[i]);
                }
                Write(connfd, buf, n);
                if(--nready==0)
                    break;
            }
        }
    }
    close(listenfd);
    return 0;
}
```

## 2. 多路IO-epoll
<sys/epoll.h>

和select差不多。将检测文件描述符的变化委托给内核去处理, 然后内核将发生变化的文件描述符对应的事件返回给应用程序。比select、poll好在会告诉哪个文件描述符发生变化。 

### 2.1 epoll_create----创建树根
int epoll_create(int size);
- **函数说明**: 创建一个树根
- **参数说明**:
	- size: 最大节点数, 此参数在linux 2.6.8已被忽略, 但必须传递一个大于0的数.
- **返回值**:
	- 成功: 返回一个大于0的文件描述符, 代表整个树的树根.
	- 失败: 返回-1, 并设置errno值.


### 2.2 epoll_ctl----添加, 删除和修改要监听的节点
 int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
 函数相关的结构体：
```cpp
  typedef union epoll_data {
      void        *ptr;
      int          fd;
      uint32_t     u32;
      uint64_t     u64;
  } epoll_data_t;

  struct epoll_event {
      uint32_t     events; //要内核监控的什么类型事件
      epoll_data_t data; //监控哪个文件描述符
  };
  ```

event.events常用的有:
- EPOLLIN: 读事件
- EPOLLOUT: 写事件
- EPOLLERR: 错误事件
- EPOLLET: 边缘触发模式（默认水平触发模式）
 
 int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
- **函数说明**: 在epoll树上添加, 删除和修改要监听的节点
- **参数说明**:
	- epfd: epoll树根
	- op:
		- EPOLL_CTL_ADD: 从树上添加事件
		- EPOLL_CTL_DEL: 从树上删除事件
		- EPOLL_CTL_MOD: 从树上修改事件
	- fd: 事件节点对应的文件描述符
	- event: 要操作的事件结构体节点。
		- events:
			- EPOLLIN表示读事件
			- EPOLLOUT表示写事件
			- EPOLLERR表示异常事件
			- EPOLLET: 边缘触发模式（默认水平触发模式）
		- data:
			- fd :表示要监控的文件描述符

```cpp
//用法：
struct epoll_event ev;
ev.events = EPOLLIN;//监听读事件
ev.data.fd=listenfd;
epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
```
### 2.3 epoll_wait----委托内核监控
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
- **函数说明**:委托内核监控epoll树的节点（就像select函数一样），阻塞函数
-  **参数说明**:
	- epfd: epoll树根
	- events: 传出参数, 发生变化的事件结构体**数组**
	- maxevents: events大小
	- timeout:
		- -1: 表示永久阻塞
		- 0: 立即返回
		- \>0: 表示超时等待事件
- **返回值:**
	- 成功: 返回发生事件的个数
	- 失败: 若timeout=0, 没有事件发生则返回; 返回-1, 设置errno值, 
- 注意：epoll_wait返回的数组中事件节点的值不会修改，是当时上epoll树的时候设置的值。

### 2.4 利用epoll开发高并发服务器
需求：利用单进程和epoll完成多个客户端的连接。注意：在用epoll开发服务器中，主要用epoll干两件事：
- 监听客户端的connect
- 监听客户端的发送的数据  
```cpp
//第四章：epoll开发服务器代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "wrap.h"
#include <sys/epoll.h>

int main()
{
    struct epoll_event ev;

    int nready;
    //该结构体数组用于接收epoll_wait返回的值
    struct epoll_event c_events[1024];
    int i;
    int connfd;

    //发送数据相关
    int n;
    char buf[1024];

    //获取客户端信息相关
    struct sockaddr_in cliaddr;
    char sIP[16];
    socklen_t len = sizeof(cliaddr);

    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    //允许端口复用
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    //绑定
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    Bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    //监听
    Listen(listenfd, 128);
    printf("listening\n");
    //创建一棵epoll树
    int epfd = epoll_create(1);
    if(epfd<0)
    {
        perror("create epoll error");
        return -1;
    }

    //将监听文件描述符上树
    ev.events = EPOLLIN;
    ev.data.fd = listenfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    while(1)
    {
        nready = epoll_wait(epfd, c_events, 1024, -1);//委托内核监听，阻塞，直到有事件发生
        if(nready < 0)
        {
            if(errno == EINTR)
                continue;
            break;
        }
        //两种会取消阻塞：1、listenfd 2、connfd
        for(i=0;i<nready;++i)
        {
            //1、有客户端连接请求到来
            if(c_events[i].data.fd == listenfd)
            {
                connfd = Accept(listenfd,(struct sockaddr*)&cliaddr, &len);
                printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET, &cliaddr.sin_addr.s_addr, sIP,sizeof(sIP)), ntohs(cliaddr.sin_port));
                //新连接的客户节点上树
                ev.events = EPOLLIN;
                ev.data.fd = connfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
                continue;
            }
            //2、有客户端数据发来
            connfd = c_events[i].data.fd;
            memset(buf,0x00,sizeof(buf));
            n = Read(connfd, buf, sizeof(buf));
            if(n<=1)
            {
                close(connfd);
                printf("client closed\n");
                //从epoll树上删除节点
                epoll_ctl(epfd, EPOLL_CTL_DEL,connfd, NULL);
                continue;
            }
            printf("%s", buf);
            int k;
            for(k=0;k<n;++k)
            {
                buf[k]  = toupper(buf[k]);
            }
            Write(connfd, buf, n);
        }
    }
    Close(epfd);
    close(listenfd);
    return 0;
}
```

### 2.5 epoll的LT和ET模式
epoll的两种模式LT和ET模式
- LT(水平触发): 高电平代表1
	- 以读事件为例，当缓冲区有数据准备好的时候，此时会触发读事件，如果我们一直不去读取缓冲区里的数据，epoll模型就会一直通知我们有事件就绪，即epoll_wait中的events参数就会一直包含某个文件描述符的读事件。

- ET(边缘触发): 电平有变化就代表1
	- ET模式与LT模式相反，当缓冲区就数据准备好的时候，也会触发读事件，但是只会触发一次，如果我们这次没有调用read/recv读取 或者 没有一次读完，后面就不会通知有读事件就绪了。简单来说，只有当缓冲区里的数据量发生变化的时候，才会通知我们一次，不会像LT模式那样一直通知。换句话说：**只有当I/O状态改变时，才触发事件，每次触发一次性把数据全部处理完，因为下一次处理要等I/O状态再次改变才可以(触发就全部处理完数据)**
	
具体来说：
- epoll默认情况下是LT模式, 在这种模式下, 若读数据一次性没有读完, 缓冲区中还有可读数据, 则epoll_wait还会再次通知
- 若将epoll设置为ET模式, 若读数据的时候一次性没有读完, 则epoll_wait不再通知,直到下次有新的数据发来.

如何设置EPOLLET:	
```cpp
struct epoll_event ev;
ev.events = EPOLLIN | EPOLLET;
ev.data.fd = connfd;
epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
```
### 2.6 epoll的ET模式的read非阻塞形式
为什么ET模式下read要设置成非阻塞形式：
假设客户端给服务端发送了一个大小为100K byte的数据，读事件就绪，epoll模型通知你一次，但是服务端一次没有读完，还剩余50K在缓冲区里。等到下一次调用epoll_wait的时候，由于epoll是ET模式，已经通知过你一次，这次就不认为sock有读事件就绪，epoll_wait 也就不会返回该文件描述符上读事件就绪的信息。

因此，我们需要在epoll_wait返回一次的情况下读完数据，所以我们需要使用循环while(1)。而使用循环读数据, 直到读完数据之后会阻塞，所以要将将通信文件描述符设置为非阻塞模式

**使用ET模式的两个要求**：
- 要求一：**必须要一次读完/写入所有的数据**。因为ET模式只会通知一次，下一次读取只能是缓冲区接收到了新的数据。
- 要求二：**必须设为非阻塞模式**。循环读取的时候，如果缓冲区没有数据或者低于水位线，recv/read就会阻塞等待读事件就绪，这会影响到epoll模型中其他文件描述符的操作。

具体代码案例移步至：https://github.com/jiong1998/unix_socket.io/issues/8

## 3 epoll反应堆

### 3.1 epoll反应堆的核心思想
在前面我们提过epoll结构体上树的相关结构体和函数如下所示。

 int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
 函数相关的结构体：
```cpp
  typedef union epoll_data {
      void        *ptr;
      int          fd;
      uint32_t     u32;
      uint64_t     u64;
  } epoll_data_t;

  struct epoll_event {
      uint32_t     events; //要内核监控的什么类型事件
      epoll_data_t data; //监控哪个文件描述符
  };
  ```

在之前我们都是用联合体中的fd成员，在epoll反应堆模型设计中，我们将替换成使用void *ptr，void * 意味着他能指向任意类型，我们令其指向一个结构体，结构体中的至少含有三个成员：
- 文件描述符
- 事件（EPOLLIN、EPOLLOUT、EPOLLERR）
- 回调函数（重点）
![在这里插入图片描述](https://img-blog.csdnimg.cn/f24b47f165e34323a7263cdb4fbf5fec.png)

把这段看懂就看懂epoll反应堆的思想了：
这就意味着，只要epoll_wait返回的时候，就会返回有变化的事件节点，**节点中保存的事件信息就是ptr指向的结构体信息**，也就能获取对应的文件描述符，事件，和回调函数，
因此**内核就可以调用结构体中的回调函数处理该事件**。这种思想利用了C++封装的思想，一个事件的产生会触发一系列连锁反应，事件产生之后最终调用的是回调函数。

![### 3.2 利用epoll反应堆开发高并发服务器流程!\[请添加图片描述\](https://img-blog.csdnimg.cn/1251e45d754442bb83b871e6a0678b3d.png)](https://img-blog.csdnimg.cn/afdf9222723241f7ab8c739f1d02518e.png)

# 第五章 线程池
## 1. 线程池

### 1.1线程池概念
什么是线程池? 
&emsp;&emsp;是一个抽象的概念, 若干个线程组合到一起, 形成线程池.

为什么需要线程池? 
	&emsp;&emsp;多线程版服务器一个客户端就需要创建一个线程! 若客户端太多, 显然不太合适.

什么时候需要创建线程池呢？简单的说，**如果一个应用需要频繁的创建和销毁线程，而任务执行的时间又非常短**，这样线程创建和销毁的带来的开销就不容忽视，这时也是线程池该出场的机会了。如果线程创建和销毁时间相比任务执行时间可以忽略不计，则没有必要使用线程池了。

线程池和任务池:
&emsp;&emsp;任务池相当于共享资源, 所以需要使用互斥锁, 当任务池中没有任务的时候需要让线程阻塞, 所以需要使用条件变量.

如何让线程执行不同的任务?
&emsp;&emsp;对于任务池中的每个元素，都是一个结构体数组，其中存储了回调函数。 在任务中使用回调函数, 这样可以起到不同的任务执行不同的函数。所以促成的结果就是创建子线程的时候执行的动作都一样，但是执行子线程的时候有各自的回调函数去执行不同的操作。

主线程负责添加任务，子线程负责从任务中获取任务并处理任务

# 第六章 UDP套接字
UDP：用户数据报协议 
- 面向无连接的，不稳定，不可靠，不安全的数据报传递---更像是收发短信
- UDP传输不需要建立连接，传输效率更高，在稳定的局域网内环境相对可

SOCK_DGRAM

## 1. recvfrom----接收信息
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);
- 函数说明: 接收消息，会阻塞
- 参数说明:
	- sockfd 套接字
	- buf  要接受的缓冲区
	- len  缓冲区的长度
	- flags 标志位 一般填0
	- src_addr 传出参数，发送方的地址  
	- addrlen  发送方地址长度 
- 返回值
	- 成功: 返回读到的字节数 
	- 失败: 返回 -1 设置errno 

调用该函数相当于TCP通信的recv+accept函数

## 2. sendto----发送数据
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);

- 函数说明: 发送数据
- 参数说明:
	- sockfd 套接字
	- buf  要接受的缓冲区
	- len  发送的长度
	- flags 标志位 一般填0
	- dest_addr 目的地址
	- addrlen 目的地址长度
- 返回值
	- 成功: 返回写入的字节数
	- 失败: 返回-1，设置errno 

## 3. udp服务器开发代码
udp天然支持多客户端

需求：客户端连接服务器后，客户端将内容传输到服务器端，服务器输出客户端的内容，并将客户端的内容改成大写并传输回客户端，客户端输出服务器的传输的内容。
```cpp
//第五章：udp开发服务器代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "wrap.h"

int main()
{
    int connfd = Socket(AF_INET, SOCK_DGRAM, 0);
    //绑定
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    inet_pton(AF_INET, "192.168.1.213", &servaddr.sin_addr.s_addr);
    Bind(connfd, (struct sockaddr *)& servaddr, sizeof(servaddr));

    struct sockaddr_in cliaddr;
    socklen_t len；
    char buf[1024];
    int n;
    printf("等待用户连接输入信息中...\n");
    while(1)
    {
        bzero(&cliaddr, sizeof(cliaddr));
        len = sizeof(cliaddr);
        memset(buf,0x00, sizeof(buf));
        n = recvfrom(connfd, buf, sizeof(buf), 0, (struct sockaddr *)& cliaddr, &len);

        printf("客户端:%d----->%s\n", ntohs(cliaddr.sin_port),buf);
        int k;
        for(k=0;k<n;++k)
        {
            buf[k]  = toupper(buf[k]);
        }
        sendto(connfd, buf, n, 0, (struct sockaddr *)& cliaddr, len);
    }
    close(connfd);
    return 0;
}
```

## 4. udp客户端开发代码
```cpp
//第五章：udp开发客户端代码
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include "wrap.h"

int main()
{
    int connfd = Socket(AF_INET, SOCK_DGRAM, 0);

    //填写服务器的信息
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    inet_pton(AF_INET, "192.168.1.213", &servaddr.sin_addr.s_addr);
    socklen_t len = sizeof(servaddr);

    char buf[1024];
    int n;
    printf("请输入内容\n");
    while(1)
    {
        //读标准输入数据
        memset(buf, 0x00, sizeof(buf));
        n = Read(STDIN_FILENO,buf,sizeof(buf));

        //发送数据
        sendto(connfd, buf, n, 0, (struct sockaddr *)& servaddr, len);

        //接收数据
        memset(buf, 0x00, sizeof(buf));
        n = recvfrom(connfd, buf, sizeof(buf), 0,  NULL, NULL);
        if( n <=1)
        {
            printf("read error or server closed, n==[%d] \n", n);
            break;
        }
        printf("%s", buf);
    }
    close(connfd);
    return 0;
}
```
## 5. 本地socket通信
通过socket函数创建本地套接字
函数参数填写:	
- domain: AF_UNIX or AF_LOCAL
- type: SOCK_STREAM或者SOCK_DGRAM
- protocol: 0 表示使用默认协议

创建socket成功以后, 会在内核创建缓冲区, 下图是客户端和服务端内核缓冲区示意图.

![在这里插入图片描述](https://img-blog.csdnimg.cn/e004b93f64a846b18356803b8c6fd3f1.png)
通过bind绑定本地套接字
- socket: 由socket函数返回的文件描述符
- addr: 本地地址
- addlen: 本地地址长度
- 相关结构体：
struct sockaddr_un {
    sa_family_t sun_family;  /* AF_UNIX or AF_LOCAL*/
    char sun_path[108];  //文件路径
};
![在这里插入图片描述](https://img-blog.csdnimg.cn/783d14d517394a96b4c0f59bc8b063a6.png)

需要注意的是: **bind函数会自动创建socket文件**, 若在调用bind函数之前socket文件已经存在, 则调用bind会报错, 可以使用unlink函数在bind之前先删除文件.

代码和之前服务器-客户端开发差不多（但是在本地通信中，客户端要绑定自己的.sock文件，不然服务器不知道你是谁），就不放上来了。

# 第七章 libevent
libevent的核心实现:
&emsp;&emsp;在linux上, 其实质就是epoll反应堆.
&emsp;&emsp;libevent是事件驱动, epoll反应堆也是事件驱动, 当要监测的事件发生的时候, 就会调用事件对应的回调函数, 执行相应操作. 特别提醒: 事件回调函数是由用户开发的, 但是不是由用户显示去调用的, 而是由libevent去调用的.

## 1.安装
按照教程安装，安装完后会提示：
error while loading shared libraries: libevent-2.0.so.5

原因是：默认情况下，系统只会使用/lib和/usr/lib这两个目录下的库文件，通常通过源码包进行安装时，如果没有指定，会将库安装在/usr/local/lib目录下当运行程序需要链接动态库时，提示找不到相关的.so库，会提示报错。那么就需要将不在默认库目录中的目录添加到配置文件中去。

解决办法：
1.打开/etc/ld.so.conf配置文件
&emsp;&emsp;vim /etc/ld.so.conf
2.添加库文件所在的目录
&emsp;&emsp;/usr/local/lib
3.保存修改后，执行：/sbin/ldconfig -v
&emsp;&emsp;其作用是将文件/etc/ld.so.conf列出的路径下的库文件缓存到/etc/ld.so.cache以供使用，因此当安装完一些库文件，或者修改/etc/ld.so.conf增加了库的新搜索路径，需要运行一下ldconfig，使所有的库文件都被缓存到文件/etc/ld.so.cache中，如果没做，可能会找不到刚安装的库。

&emsp;&emsp;如果进行这几步处理后，出现了error while loading shared libraries:...：permission denied
需要确认一下是不是当前用户在库目录下是不是没有可读的权限。
将提示中显示的文件权限进行修改，添加可读权限，随后报错解除

使用方法：
gcc -o hello-world hello-world.c -levent
## 2. libevent的地基-event_base
使用libevent 函数之前需要分配一个或者多个 event_base 结构体, 每个event_base结构体持有一个事件集合, 可以检测以确定哪个事件是激活的, event_base结构相当于epoll红黑树的树根节点, 每个event_base都有一种用于检测某种事件已经就绪的 “方法”(回调函数)

通常情况下可以通过event_base_new函数获得event_base结构。

### 2.1 event_base----创建地基
相关函数说明:
1 struct event_base *event_base_new(void);    //event.h的L:337
- 函数说明: 获得event_base结构
- 参数说明: 无
- 返回值: 
	- 成功返回event_base结构体指针;
	- 失败返回NULL;

### 2.2 event_free----释放地基
2 void event_base_free(struct event_base *);   //event.h的L:561
- 函数说明: 释放event_base指针

### 2.3 event_reinit----子进程调用地基
3 int event_reinit(struct event_base *base);  //event.h的L:349
- 函数说明: **如果有子进程,** 且子进程也要使用base, 则子进程需要对event_base重新初始化, 此时需要调用event_reinit函数.
- 函数参数: 由event_base_new返回的执行event_base结构的指针
- 返回值: 成功返回0, 失败返回-1

对于不同系统而言, event_base就是调用不同的多路IO接口去判断事件是否已经被激活, 对于linux系统而言, 核心调用的就是epoll, 同时支持poll和select.

### 2.4 看libevent支持的后端的方法
查看libevent支持的后端的方法有哪些:
const char \**event_get_supported_methods(void);
- 函数说明: 获得当前系统(或者称为平台)支持的方法有哪些
- 参数: 无
- 返回值: 返回二维数组, 类似与main函数的第二个参数**argv.

const char * event_base_get_method(const struct event_base *base);
- 函数说明: 获得当前base节点使用的多路io方法
- 函数参数: event_base结构的base指针.
- 返回值: 获得当前base节点使用的多路io方法的指针

## 3. 事件的构建与使用
### 3.1 event_new函数----创建event事件
某个事件所对应的回调函数：
typedef void (*event_callback_fn)(evutil_socket_t fd, short events, void *arg);
注意: 回调函数的参数就对应于event_new函数的fd, event和arg

struct event *event_new(struct event_base *base, evutil_socket_t fd, short events, event_callback_fn cb, void *arg);

- 函数说明: event_new负责创建event结构指针, 同时指定对应的地基base, 		  还有对应的文件描述符, 事件, 以及回调函数和回调函数的参数。
- 参数说明：
	- base: 对应的根节点--地基
	- fd: 要监听的文件描述符
	- events:要监听的事件
		- EV_READ  读事件
		- EV_WRITE  写事件
		- EV_SIGNAL  信号事件
		- EV_PERSIST  周期性触发
		- 若设置持续的读事件：EV_READ | EV_PERSIST

### 3.2 event_add函数----将事件上树
int event_add(struct event *ev, const struct timeval *timeout);
- 函数说明: 将非未决态事件转为未决态, 相当于调用epoll_ctl函数(EPOLL_CTL_ADD), 开始监听事件是否产生, 相当于epoll的上树操作.
- 参数说明：
	- ev: 调用event_new创建的事件
	- timeout: 限时等待事件的产生, 也可以设置为NULL, 没有限时。

### 3.3 event_del函数----将事件下树
int event_del(struct event *ev);
- 函数说明: 将事件从未决态变为非未决态, 相当于epoll的下树（epoll_ctl调用EPOLL_CTL_DEL操作）操作。
- 参数说明: ev指的是由event_new创建的事件.

### 3.4 event_free函数----释放事件节点
void event_free(struct event *ev);
- 函数说明: 释放由event_new申请的event节点。
## 4. 等待事件产生-循环等待event_loop		
&emsp;&emsp;libevent在地基打好之后, 需要等待事件的产生, 也就是等待事件被激活, 所以程序不能退出, 对于epoll来说, 我们需要自己控制循环, 而在libevent中也给我们提供了API接口, 类似where(1)的功能. 



### 4.1 event_base_dispatch----创建循环
int event_base_dispatch(struct event_base *base);   //event.h的L:364
- 函数说明: 进入循环等待事件
- 参数说明:由event_base_new函数返回的指向event_base结构的指针
- 调用该函数, 程序将会一直运行, 直到没有需要检测的事件了, 或者被结束循环的API终止。

### 4.2 event_base_loopexit/loopbreak----结束循环

struct timeval {
	long    tv_sec;                    
	long    tv_usec;            
};//设置时间

int event_base_loopexit(struct event_base *base, const struct timeval *tv);

int event_base_loopbreak(struct event_base *base);

两个函数的区别是如果正在执行激活事件的回调函数, 那么**event_base_loopexit将在事件回调执行结束后终止循环**（如果tv时间非NULL, 那么将等待tv设置的时间后立即结束循环，而**event_base_loopbreak会立即终止循环**。






## 5. 使用libevent库的步骤
1. 创建根节点--event_base_new
2. **设置监听事件和数据可读可写的事件的回调函数**
设置了事件对应的回调函数以后, 当事件产生的时候会自动调用回调函数
3. 事件循环--event_base_dispatch
相当于while(1), 在循环内部等待事件的发生,  若有事件发生则会触发事件对应的回调函数。
4. 释放根节点--event_base_free
  释放由event_base_new和event_new创建的资源, 分别调用event_base_free和event_free函数.

## 6. 基于libevent实现tcp服务器流程
```cpp
1 创建socket---socket()
2 设置端口复用---setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int))
3 绑定--bind()
4 设置监听--listen()
5 创建地基
	struct event_base *base = event_base_new()
6 创建lfd对应的事件
	struct event *ev = event_new(base, lfd, EV_READ|EV_PERSIST, conncb, base);
7 上event_base地基
	event_add(ev, NULL);
8 进入事件循环
	event_base_dispatch(base);
	
9 释放资源
	event_base_free(base);
	event_free(ev);
	
//编写回调函数：
//typedef void (*event_callback_fn)(evutil_socket_t fd, short events, void *arg);
//监听文件描述符对应的事件回调函数
void conncb(evutil_socket_t fd, short events, void *arg)
{
	struct event_base *base = (struct event_base *)arg;
	//接受新的连接
	int cfd = accept(fd, NULL, NULL);
	if(cfd>0)
	{
		//创建一个新的事件
		struct event *ev = event_new(base, cfd, EV_READ|EV_PERSIST, readcb, NULL);
		event_add(ev, NULL);
	}
}

//读客户端数据对应的回调函数
void readcb(evutil_socket_t fd, short events, void *arg)
{	
	//读数据
	n = read(fd, buf, sizeof(buf));
	if(n<=0)
	{
		//从base地基上删除该事件
		close(fd);
		event_del(ev);
		event_free(ev);
	}
	//发送数据给对方
	write(fd, buf, n);
}
```

## 7.基于libevent实现tcp服务器代码
```cpp
//第六章：基于libevent实现tcp服务器
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>//大小写转换
#include <fcntl.h>
#include <event2/event.h>
#include <unistd.h>

//利用结构体数组存储connfd和对应的event
struct Ev_Connfd_Struct
{
    struct event * event;
    evutil_socket_t connfd;
};
struct Ev_Connfd_Struct ev_confd_struct[1024];
//初始化结构体数组
void Init_Ev_Connfd_Struct(struct Ev_Connfd_Struct * ev_confd_struct, int length)
{
    int i=0;
    for(i=0;i<length;++i)
    {
        ev_confd_struct[i].connfd = -1;
        ev_confd_struct[i].event = NULL;
    }
    return;
}
//查找结构体数组一个空闲位置
int find_index(struct Ev_Connfd_Struct * ev_confd_struct, int length)
{
    int i=0;
    for(i=0;i<length;++i)
    {
        if(ev_confd_struct[i].connfd==-1)
            return i;
    }
    return -1;
}
int find_connfd(struct Ev_Connfd_Struct * ev_confd_struct, int length, int connfd)
{
    int i=0;
    for(i=0;i<length;++i)
    {
        ev_confd_struct[i].connfd == connfd;
        return i;
    }
}



//connfd事件对应的回调函数
void readcb(evutil_socket_t fd, short events, void *arg)
{
    int i = find_connfd(ev_confd_struct, 1024, fd);
    struct event * _ev = ev_confd_struct[i].event;
    //处理客户端数据发来的事件
    int n;
    char buf[1024];
    memset(buf, 0x00, sizeof(buf));
    n = read(fd, buf, sizeof(buf));
    if(n<=1)
    {
        printf("客户端关闭连接\n");
        close(fd);
        //将通信文件描述符对应的事件从base地基上删除
        event_del(_ev);
        ev_confd_struct[i].connfd = -1;
        ev_confd_struct[i].event = NULL;
    }
    else
    {
        printf("%s", buf);
        int k;
        for(k=0;k<n;++k)
        {
            buf[k]  = toupper(buf[k]);
        }
        write(fd, buf, n);
    }
}

//listenfd事件对应的回调函数
//typedef void (*event_callback_fn)(evutil_socket_t fd, short events, void *arg);
void conncb(evutil_socket_t fd, short events, void *arg)
{
    //客户端信息相关参数
    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);
    char sIP[16];

    struct event_base *base = (struct event_base *) arg;
    //处理有客户端连接请求到来的事件
    int connfd = accept(fd, (struct sockaddr *) &cliaddr, &len);
    if (connfd > 0)
    {
        int i = find_index(ev_confd_struct,1024);
        if(i==-1)
        {
            printf("用户连接已满，请再次尝试\n");
            return;
        }
        ev_confd_struct[i].connfd=connfd;

        printf("已成功连接一个客户端,client:IP = [%s], port=[%d]\n", inet_ntop(AF_INET, &cliaddr.sin_addr.s_addr, sIP,sizeof(sIP)), ntohs(cliaddr.sin_port));

        //创建通信文件描述符对应的事件并设置回调函数为readcb
        struct event * ev_connfd = event_new(base, connfd, EV_READ | EV_PERSIST, readcb, NULL);

        //新连接上地基
        event_add(ev_connfd, NULL);
        ev_confd_struct[i].event = ev_connfd;
    }
    else
    {
        printf("accept error\n");
    }
}


int main()
{
    //初始化结构体数组
    Init_Ev_Connfd_Struct(ev_confd_struct,1024);

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);

    //允许端口复用
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    //绑定
    struct sockaddr_in servaddr, clivaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    //监听
    listen(listenfd, 128);
    printf("listening\n");

    //构建地基
    //struct event_base *event_base_new(void)
    struct event_base * base  = event_base_new();
    if(base==NULL)
    {
        printf("event_base_new error\n");
        return -1;
    }
    //创建listenfd事件
    //struct event *event_new(struct event_base *base, evutil_socket_t fd,
    //                      short events, event_callback_fn cb, void *arg);
    struct event * ev = event_new(base, listenfd, EV_READ | EV_PERSIST, conncb, base);//conncb为回调函数
    if(ev==NULL)
    {
        printf("event_new error\n");
        return -1;
    }
    //将listenfd事件上event_base地基
    event_add(ev, NULL);

    //进入事件循环
    event_base_dispatch(base);

    //释放资源
    event_base_free(base);
    event_free(ev);

    close(listenfd);
    return 0;
}
```

## 8. 自带buffer的事件-bufferevent
bufferevent实际上也是一个event, 只不过比普通的event高级一些, 它的内部有两个缓冲区, 以及一个文件描述符（网络套接字）。所以一共有四个缓冲区。 还有就是libevent事件驱动的核心回调函数, 那么四个缓冲区以及触发回调的关系如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/85bd004769ec4932964fd4a9ce2967dd.png)
从图中可以得知, 一个bufferevent对应两个缓冲区, 三个回调函数, 分别是写回调, 读回调和事件回调。<font color='red'> **我们在对数据进行读写操作时是写入bufferevent的缓冲区，bufferevent的缓冲区会自动帮我们写入sockfd的缓冲区中。** </font>

bufferevent有三个回调函数：
- 读回调 – 当bufferevent自动将底层读缓冲区的数据读到自身的读缓冲区时触发读事件回调.需要注意的是: 数据由内核到bufferevent的过程不是用户程序执行的, 是由bufferevent内部操作的.
- 写回调 – 当用户程序将数据写到bufferevent的写缓冲区之后, bufferevent会自动将数据写到内核的写缓冲区，此时触发写回调函数，最终有内核程序将数据发送出去。
- 事件回调 – 当bufferevent绑定的socket连接, 断开或者异常的时候触发事件回调.

### 8.1 bufferevent_socket_new----创建bufferevent事件（将每一个connfd与一个bufferevent缓冲区绑定）
struct bufferevent *bufferevent_socket_new(struct event_base *base, evutil_socket_t fd, int options);
- 函数说明: bufferevent_socket_new 对已经存在connfd创建bufferevent事件, 可用于后面讲到的连接监听器的回调函数中.即：**将connfd与bufferevent缓冲区绑定**。
- 参数说明：
	- base :对应根节点
	- fd   :文件描述符
	- options : bufferevent的选项
		- BEV_OPT_CLOSE_ON_FREE  -- 释放bufferevent自动关闭底层接口(当bufferevent被释放以后, 文件描述符也随之被close)    
		- BEV_OPT_THREADSAFE  -- 使bufferevent能够在多线程下是安全的

### 8.2 bufferevent_free----释放bufferevent
void bufferevent_free(struct bufferevent *bufev);

### 8.3 bufferevent_socket_connect----与通信的socket绑定（客户端用）

int bufferevent_socket_connect(struct bufferevent *bev, struct sockaddr *serv, int socklen);
- 函数说明: 该函数封装了底层的socket与connect接口, 通过调用此函数, **可以将bufferevent事件与通信的socket进行绑定**。
- 函数参数：
	- bev – 需要提前初始化的bufferevent事件
	- serv – 对端(一般指服务端)的ip地址, 端口, 协议的结构指针
	-	socklen – 描述serv的长度

说明: 调用此函数以后, 通信的socket与bufferevent缓冲区做了绑定, 后面调用了bufferevent_setcb函数以后, 会对bufferevent缓冲区的读写操作的事件设置回调函数, **当往缓冲区中写数据的时候会触发写回调函数, 当数据从socket的内核缓冲区读到bufferevent读缓冲区中的时候会触发读回调函数.**



### 8.4 bufferevent_setcb----设置三个回调函数

```cpp
void bufferevent_setcb(struct bufferevent *bufev,
    			bufferevent_data_cb readcb, //读回调
    			bufferevent_data_cb writecb,//写回调
				bufferevent_event_cb eventcb, //事件回调
				void *cbarg);
```
- 函数说明: bufferevent_setcb用于设置bufferevent的回调函数, readcb, writecb, 		eventcb分别对应了读回调, 写回调, 事件回调, cbarg代表回调函数的参数。

回调函数的原型：
- 读写回调：typedef void (*bufferevent_data_cb)(struct bufferevent *bev, void *ctx);
- 事件回调：typedef void (*bufferevent_event_cb)(struct bufferevent *bev, short what, void *ctx);
	- What 代表 对应的事件
		- BEV_EVENT_EOF--遇到文件结束指示
		- BEV_EVENT_ERROR--发生错误
		- BEV_EVENT_TIMEOUT--发生超时
		- BEV_EVENT_CONNECTED--请求的过程中连接已经完成

### 8.5 bufferevent_write/read----读写bufferevent缓冲区
写缓冲区：
- int bufferevent_write(struct bufferevent *bufev, const void *data, size_t size);
- 函数说明：bufferevent_write是将data的数据写到bufferevent的写缓冲区。触发写事件回调函数

读缓冲区：
- size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size);
- bufferevent_read 是将bufferevent的读缓冲区数据读到data中, 同时将读到的数据从bufferevent的读缓冲清除。触发读事件回调函数

bufferevent_enable与bufferevent_disable是设置事件是否生效, 如果设置为disable, 事件回调将不会被触发：
- int bufferevent_enable(struct bufferevent *bufev, short event);
-  int bufferevent_disable(struct bufferevent *bufev, short event);


## 8. 链接监听器----evconnlistener
<event2/listener.h>

**链接监听器封装了底层的socket通信相关函数, 比如socket, bind, listen, accept这几个函数。** 链接监听器创建后实际上相当于调用了socket, bind, listen, 此时等待新的客户端连接到来, 如果有新的客户端连接, 那么内部先进行调用accept处理, 然后调用用户指定的回调函数。一句话总结：就是封装了socket bind listen accept函数的方法。
### 8.1 evconnlistener_new_bind----初始化链接监听器
```cpp
struct evconnlistener *evconnlistener_new_bind(
struct event_base *base, evconnlistener_cb cb, 
void *ptr, unsigned flags, int backlog,
const struct sockaddr *sa, int socklen);
```
- **函数说明:** evconnlistener_new_bind是在当前没有套接字的情况下对链接监听器进行初始化。
- **参数说明**：
	- base：地基
	- cb：自己设定的回调函数。cb是accept返回后的**回调函数**, 但是注意这个回调函数触发的**时机**, 链接器已经处理好新连接了, 并将与新连接通信的描述符交给回调函数。
	- ptr：回调函数的参数
	- flags：
		- LEV_OPT_LEAVE_SOCKETS_BLOCKING   文件描述符为阻塞的
		- **LEV_OPT_CLOSE_ON_FREE            关闭时自动释放**
		- LEV_OPT_REUSEABLE                端口复用
		- LEV_OPT_THREADSAFE               分配锁, 线程安全
	- backlog： listen函数的第二个参数，设置为-1让监听起自动设置就行
	- 最后两个参数就是bind函数的参数

evconnlistener的回调函数（**即可以看作调用完accept，accept返回以后所调用的回调函数**）：
typedef void (*evconnlistener_cb)(struct evconnlistener *evl, evutil_socket_t fd, struct sockaddr *cliaddr, int socklen, void *ptr);

注意：**回调函数fd参数是与客户端通信的描述符**, 并非是等待连接的监听的那个描述符, 所以cliaddr对应的也是新连接的对端地址信息, 已经是accept处理好的。

void evconnlistener_free(struct evconnlistener *lev);
函数说明: 释放链接监听器

int evconnlistener_enable(struct evconnlistener *lev);
函数说明: 使链接监听器生效

int evconnlistener_disable(struct evconnlistener *lev);
函数说明: 使链接监听器失效
