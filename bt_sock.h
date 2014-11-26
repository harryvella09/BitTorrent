#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/hmac.h> // need to add -lssl to compile

#ifdef DEBUG_EN
#define DEBUG(msg,var...) printf(msg,var)
#define ERROR(msg,var...) printf("ERROR: " msg,var); perror("ERROR MSG : ");
#else
#define DEBUG(msg,var...)
#define ERROR(msg,var...)
#endif



#define BUF_LEN 1024
#define FAILURE 1
#define SUCCESS 0
#define TRUE 1
#define FALSE 0
#define BACKLOG 5
#define KEYLEN 16
#define HASH_LENGTH 20

#define VERBOSE(msg,var...) if(ok_to_print == 1) printf(msg,var);
#define VERBOSE_MSG(msg) if(ok_to_print == 1) printf(msg);


void *get_in_addr(struct sockaddr *sa);
in_port_t get_in_port(struct sockaddr *sa);
int connectTopeer(char *ip,unsigned short port);

void generateRandomPortNumber(char *portno);
int create_listening_sock(char *myid);
int recvData(int sockfd, unsigned char *data, int bytesToRead);
int readData(int sockfd, unsigned char *data, int bytesToRead);
int sendData(int sockfd, unsigned char *data, int dataLen);
