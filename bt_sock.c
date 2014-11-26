#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <openssl/sha.h>
#include <fcntl.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include "bt_sock.h"
#include "bt_file.h"



extern char hname[INET6_ADDRSTRLEN];



/*Generate a ramdom port number between INIT_PORT and MAX_PORT to prepare for listening*/
void generateRandomPortNumber(char *portno)
{
  //prepare a seed and then get a random number
  srand(time(NULL) + (int)getpid());
  int port = INIT_PORT + (rand() % (MAX_PORT - INIT_PORT)) + 1;
  sprintf(portno,"%d",port);
  //printf("Random port :%d\n",port);
}

/*Returns port number. this function just provides a compatibility between IPv4 and IPv6*/
in_port_t get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return (((struct sockaddr_in*)sa)->sin_port);
    }

    return (((struct sockaddr_in6*)sa)->sin6_port);
}

/*Returns Ip address. this function just provides a compatibility between IPv4 and IPv6*/
void *get_in_addr(struct sockaddr *sa)
{
if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Create a listening socket on which a request is expected
int create_listening_sock(char *myid)
{
int sockfd;  // listen on sock_fd
struct addrinfo hints, *servinfo, *p;

int yes=1;
int rv;
//char hname[100];
char host[100];
char service[20];
char portno[5];

generateRandomPortNumber(portno);

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE; // use my IP

if (strlen(hname) == 0)
{
	gethostname(hname, sizeof hname);
}

if ((rv = getaddrinfo(hname, portno, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return 1;
}


for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1) {
        perror("server: socket");
        continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
            sizeof(int)) == -1) {
        perror("setsockopt");
        exit(FAILURE);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sockfd);
        perror("server: bind");
        continue;
    }
    break;
}

if (p == NULL)  {
    fprintf(stderr, "server: failed to bind\n");
	exit(FAILURE);
}

if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(FAILURE);
}

getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof host, service, sizeof service, 0);
inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
        host, sizeof host);

printf("Server: Socket Creation success: has TCP port number %d and IP address %s and hostname %s\n",ntohs(get_in_port((struct sockaddr *)p->ai_addr)), host,hname);
logger(LOG,"Server","Socket Creation success: has TCP port number %d and IP address %s and hostname %s\n", ntohs(get_in_port((struct sockaddr *)p->ai_addr)), host, hname);

calc_id(host, (unsigned short)ntohs(get_in_port((struct sockaddr *)p->ai_addr)), myid);

//len = sprintf(selfidstring, "%s%d", host, ntohs(get_in_port((struct sockaddr *)p->ai_addr)));
//SHA1((unsigned char *)selfidstring, len, (unsigned char *)myid);

freeaddrinfo(servinfo); // all done with this struct

return sockfd;
}




//beej's guide 
//Establishes a TCP connection with the given ip address and port number and returns the socket.
int connectTopeer(char *ip,unsigned short port)
{
	int sockfd;  
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];


	char srv_port[5];
	sprintf(srv_port,"%d",(int)port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ip, srv_port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	} 

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return -1;
	}


	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("Client: connecting to %s on port number %d\n", s,port);
	//logger(LOG,"Client","connecting to %s on port number %d\n", s, port);

	freeaddrinfo(servinfo); // all done with this structure

 return sockfd;
}





//Write data into the socket and return SUCCESS/ FAILURE status.
int sendData(int sockfd, unsigned char *data, int dataLen)
{	
	unsigned char * mydata = data;
	int bytesSent = 0, totalBytesSent = 0, bytesToSend = dataLen;
//	printf("Bytes to send: %d\nprinting hs_msg\n", bytesToSend);
	
			//write every byte of mypacket onto the socket...
			while (bytesToSend > 0)
			{
				bytesSent = write(sockfd, mydata, bytesToSend);
				if (bytesSent > 0)
				{
					//printf("%d Bytes sent successfully!!\n", bytesSent);
					totalBytesSent += bytesSent;
					bytesToSend -= bytesSent;
					mydata += bytesSent;
				}
				else
				{
					perror("Sending data failed!!");
					return FAILURE;
				}
			}

	return SUCCESS;

}


//Receive data from the socket and return SUCCESS/FAILURE status
int recvData(int sockfd, unsigned char *data, int bytesToRead)
{
	void *recvbuffer = data;
	int bytesRead = 0, yetToRead = bytesToRead, totalBytesRead = 0;
	//printf("Recv func bytesToRead from client sock : %d\n", bytesToRead);

	while (yetToRead > 0)
	{
		if ((bytesRead = read(sockfd, recvbuffer, yetToRead)) > 0)
		{
			yetToRead -= bytesRead;
			totalBytesRead += bytesRead;
			recvbuffer += bytesRead; //increment the buffer
		}
		else if (bytesRead < 0)
		{
			printf("Reading data from socket %d failed!!\n",sockfd);
			return FAILURE;
		}
		else if (bytesRead == 0)
		{
			//printf("%s : %d %s Socket Closed on the other side\n", __FILE__, __LINE__, __func__);
			logger(LOG, "ERROR", "SOCKET %d CLOSED ON THE OTHER SIDE\n",sockfd);
			return FAILURE;
		}
	}
	//printf("Data received in receive buffer is %s\n",recvbuffer);
	//printf("Recv func bytesRead from client sock : %d\n",totalBytesRead);
	
	return SUCCESS;
}



//Read data from a file socket and return the number of bytes read or FAILURE status.
int readData(int sockfd, unsigned char *data, int bytesToRead)
{
	void *recvbuffer = data;
	int bytesRead = 0, yetToRead = bytesToRead, totalBytesRead = 0;
	//printf("Recv func bytesToRead from client sock : %d\n", bytesToRead);

	while (yetToRead > 0)
	{
		if ((bytesRead = read(sockfd, recvbuffer, yetToRead)) > 0)
		{
			yetToRead -= bytesRead;
			totalBytesRead += bytesRead;
			recvbuffer += bytesRead; //increment the buffer
		}
		else if (bytesRead < 0)
		{
			printf("Reading data from socket %d failed!!\n", sockfd);
			return FAILURE;
		}
		else if (bytesRead == 0)
		{
//			printf("%s : %d %s End of file reached\n", __FILE__, __LINE__, __func__);
			break;
		}
	}
	//printf("Data received in receive buffer is %s\n",recvbuffer);
	//printf("Recv func bytesRead from client sock : %d\n",totalBytesRead);

	return totalBytesRead;
}
