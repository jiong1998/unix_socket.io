# unix_socket.io
unix网络编程卷1:个人源码+个人笔记

# Unix网络编程
在unix网络编程笔记中，大部分计算机网络的知识将被略过，默认大家有相应的前置基础。

# 第一章 Socket编程
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
	- src: 网络的整形的IP地址
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


### 5.2 服务器开发流程
1. 创建socket,返回一个文件描述符listenfd---socket()
	- 该文件描述符用于监听客户端连接
2. 将listenfd和IP、PORT进行绑定----bind()
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




