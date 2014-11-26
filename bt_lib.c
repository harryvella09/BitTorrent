#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include <pthread.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include "bt_sock.h"


extern int connections[MAX_CONNECTIONS];

extern int ok_to_print;

void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);
  
  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  peer->port = port;
    
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Internet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);

  //encode the port
  peer->sockaddr.sin_port = htons(port);
  
  //printf("peer ip address : %s\npeer port number : %d\n",(char *)inet_ntoa(peer->sockaddr.sin_addr),port);    
  calc_id((char *)inet_ntoa(peer->sockaddr.sin_addr),port,id); 
  memcpy(peer->id, id, ID_SIZE);
 
  return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x ",peer->id[i]);
    }
    printf("end of print peer\n");
  }
}

//This function is used by a seeder thread to complete the handshake procedure. This function returns handshake SUCCESS/FAILURE status.
int response_handshake(peer_t *peer,unsigned char *info_hash , unsigned char * selfid, int sockfd)//hash info
{
	handshake *hs_msg = (handshake *)malloc(sizeof(handshake));	
	// receive handshake
	if (recv_handshakemsg(hs_msg, sockfd) == FAILURE)
		return FAILURE;

	if (!compare((unsigned char *)hs_msg->protocol_name, (unsigned char *)"\x13" "BitTorrent Protocol", 19))
	{
		printf("protocol-lenth and protocol-name not matched");
		return FAILURE;
	}

	if (!compare((unsigned char *)hs_msg->info_hash, (unsigned char *)info_hash, 20))
	{
		printf("info hash not matched");
		return FAILURE;
	}
	
	free(hs_msg);


	//if matching, send the response handshake
	
	hs_msg = create_handshake(info_hash,selfid);//our id 
	if (send_handshakemsg(hs_msg, sockfd) == FAILURE)
		return FAILURE;

	free(hs_msg);

	return SUCCESS;

}

//Sends a handshake message hs_msg into the sockfd
int send_handshakemsg(handshake *hs_msg, int sockfd)
{
	
	void *sendbuf = NULL;

	sendbuf = give_mem(sendbuf, 20);
	memcpy(sendbuf, hs_msg->protocol_name, 20);
	if (sendData(sockfd, sendbuf, 20) == FAILURE)
	{
		printf("Sending protocol_name failed\n");
		return FAILURE;
	}

	memcpy(sendbuf, hs_msg->info_hash, 20);
	if (sendData(sockfd, sendbuf, 20) == FAILURE)
	{
		printf("Sending info_hash failed\n");
		return FAILURE;
	}
	//send peer id - 20 bytes

	memcpy(sendbuf, hs_msg->peer_id, 20);
	if (sendData(sockfd, sendbuf, 20) == FAILURE)
	{
		printf("Sending peer_id failed\n");
		return FAILURE;
	}
	free(sendbuf);
	return SUCCESS;
}

//Rellocates memory to ptr to a given size.
void *give_mem(void * ptr,int size)
{
	ptr = (void *)realloc(ptr,size);
	bzero(ptr,size);
	return ptr;
}


//Receives handshake from the socket and populates it in the hs_msg structure.
int recv_handshakemsg(handshake *hs_msg, int sockfd)
{
	unsigned char *recvbuf = NULL;
	recvbuf = give_mem(recvbuf, 20);
	if (recvData(sockfd, recvbuf, 20) == FAILURE)
	{
		printf("Receiving protocol-length and protocol_name failed\n");
		return FAILURE;
	}
	memcpy(hs_msg->protocol_name, recvbuf, 20);
	if (recvData(sockfd, recvbuf, 20) == FAILURE)
	{
		printf("Receiving info_hash failed\n");
		return FAILURE;
	}
	
	memcpy(hs_msg->info_hash,recvbuf,20);
	//recv peer id - 20 bytes hs_msg->peer_id
	if (recvData(sockfd, recvbuf, 20) == FAILURE)
	{
		printf("Receiving info_hash failed\n");
		return FAILURE;
	}
	memcpy(hs_msg->peer_id, recvbuf, 20);

	free(recvbuf);

	return SUCCESS;
}



//This function handles the handshake protocol for a leecher.
int init_handshake(peer_t *peer,unsigned char *hashinfo, unsigned char * selfid, int sockfd)//hash info
{
	int i = 0;
	handshake *hs_msg;

	//create and send a handshake msg
	hs_msg = create_handshake(hashinfo,selfid);//our id
	
	if (send_handshakemsg(hs_msg, sockfd) == FAILURE)
	{
		printf("Sending the handshake msg failed\n");
		return FAILURE;
	}
	
	// receive handshake
	if (recv_handshakemsg(hs_msg, sockfd) == FAILURE)
	{
		printf("Receiving data failed\n");
		return FAILURE;
	}
	
	//checks the values, if not matching drop the connection
	
	if (!compare((unsigned char *)hs_msg->protocol_name, (unsigned char *)"\x13" "BitTorrent Protocol", 20))
	{
		printf("Protocol-length and Protocol-Name not matched\n");
		return FAILURE;
	}
	
	if (!compare((unsigned char *)hs_msg->info_hash, (unsigned char *)hashinfo, 20))
	{
		printf("info hash not matched\n");
		return FAILURE;
	}
	
	PRINT("PeerId Received: ");
	for (i = 0; i < 20; i++) PRINT("0x%02x ", (unsigned char)(hs_msg->peer_id[i]));
	PRINT("\nCalculated PeerId: ");
	for (i = 0; i < 20; i++) PRINT("0x%02x ", (unsigned char)(peer->id[i]));
	PRINT("\n");

	if (!compare((unsigned char *)hs_msg->peer_id, (unsigned char *)peer->id, 20))
	{
		printf("peer id not matched\n");
		return FAILURE;
	}
	free(hs_msg);
	
	return SUCCESS;

}



//Comapres msg and comparewith byte wise upto length len
int compare(unsigned char *msg,unsigned char *comparewith,int len)
{
  int i = 0;
  for(i = 0;i < len;i++)
  {
	if(!(*(msg + i) ^ *(comparewith + i)))
	{
		//hash matched
	//	printf("%d: msg %.02x == cmp %.02x\n",i,*(msg + i),*(comparewith + i));
	}
	else
	{
	//	printf("%d: msg %.02x != cmp %.02x\n",i,*(msg + i),*(comparewith + i));
		return FALSE;
	}

  }

  return TRUE;

}



//Returns a handshake msg structure based on the peer_id and hash_info value parsed.
handshake * create_handshake(unsigned char * md, unsigned char * peer_id)
{	
handshake *msg = (handshake *)malloc(sizeof(handshake));
char proto_name[21] = "\x13" "BitTorrent Protocol";
int i;
//msg->namelength = 19;
msg->reserved = 0;

bzero(msg->protocol_name,20);
bzero(msg->info_hash,20);
bzero(msg->peer_id,20);

memcpy((char *)msg->protocol_name, (char *)proto_name, 20);
memcpy((char *)msg->info_hash, (char *)md, 20);
memcpy((char *)msg->peer_id, (char *)peer_id, 20);

PRINT("\n------------------------------------------------\n");
PRINT("\nHandshake message sent: \n\tprotocol name length is %u \n\tprotocol name is %.20s\n\treserved is %lli\n",msg->protocol_name[0],msg->protocol_name,msg->reserved);
PRINT("\n\thashofinfo is ");
for (i = 0; i < 20; i++) PRINT("0x%02x ", (unsigned char)(msg->info_hash[i]));
PRINT("\n\tpeer_id is ");
for (i = 0; i < 20; i++) PRINT("0x%02x ", (unsigned char)(msg->peer_id[i]));
PRINT("\n------------------------------------------------\n");

return msg;
}



//Extracts the bt_info_t from a be_node structure and populates md with hash of info dict.
bt_info_t * extract_info(be_node * oldnode, char * md)
{
	be_node * info_node;
	be_node * temp_node;
	char *info = NULL;
	char *temp = NULL;
	int bytescopied = 0;
	int i, j, size = 0;
	bt_info_t *bt_info = (bt_info_t *)malloc(sizeof(bt_info_t));
	bt_info->length = 0;
	bt_info->piece_length = 0;

	info = (char *)malloc(512);
	bzero(info, 512);

	//Copying url of the tracker
	info_node = oldnode->val.d[0].val;
	bzero(bt_info->announce, FILE_NAME_MAX);
	strcpy(bt_info->announce, info_node->val.s);
//	printf("bt_info->announce : %s\n", bt_info->announce);

	//Copying the info dictionary values
	info_node = oldnode->val.d[2].val;

	for (i = 0; info_node->val.d[i].val; ++i) {

//		printf("node->val.d[%d].key :%s => ", i, info_node->val.d[i].key);
		temp_node = info_node->val.d[i].val;
		switch (temp_node->type) {
		case BE_STR:
//			printf("str = %s (len = %lli)\n", temp_node->val.s, be_str_len(temp_node));
			size = be_str_len(temp_node);
//			printf("Value of size is %d\n", size);

			if ((strcmp(info_node->val.d[i].key, "name")) == 0)
			{
				bzero(bt_info->name, FILE_NAME_MAX);
				memcpy(bt_info->name, temp_node->val.s, size);
//				printf("bt_info->name : %s\n", bt_info->name);
			}

			if ((strcmp(info_node->val.d[i].key, "pieces")) == 0)
			{
				if ((bt_info->length != 0) && (bt_info->piece_length != 0))
				{
					if (bt_info->length % bt_info->piece_length == 0)
						bt_info->num_pieces = (bt_info->length / bt_info->piece_length);
					else
						bt_info->num_pieces = (bt_info->length / bt_info->piece_length) + 1;

//					printf("bt_info->num_pieces : %d\n", bt_info->num_pieces);

				}


				bt_info->piece_hashes = (char**)malloc(bt_info->num_pieces * sizeof(char*));
				for (j = 0; j < bt_info->num_pieces; j++)
				{
					bt_info->piece_hashes[j] = (char*)malloc(HASH_LENGTH);
					bzero(bt_info->piece_hashes[j], HASH_LENGTH);
					memcpy(bt_info->piece_hashes[j], temp_node->val.s, HASH_LENGTH);
//					printf("bt_info->piece_hashes[%d] : %.20s\n", j, bt_info->piece_hashes[j]);
					temp_node->val.s += 20;

				}

//				printf("bt_info->piece_hashes[2] : %.20s\n", bt_info->piece_hashes[2]);
			}
			break;

		case BE_INT:
//			printf("int = %lli\n", temp_node->val.i);
			size = sizeof(long long);
			//printf("Value of size is %d\n",size);

			if ((strcmp(info_node->val.d[i].key, "length")) == 0)
			{
				bt_info->length = (int)temp_node->val.i;
//				printf("bt_info->length : %d\n", bt_info->length);
			}

			if ((strcmp(info_node->val.d[i].key, "piece length")) == 0)
			{
				bt_info->piece_length = (int)temp_node->val.i;
//				printf("bt_info->piece_length : %d\n", bt_info->piece_length);
			}


			break;


		case BE_LIST:   // TO AVOID WARNINGS
			break;

		case BE_DICT:	//TO AVOID WARNINGS
			break;
		}



	}
	bytescopied = sprintf(info, "%d%s%d", bt_info->length, bt_info->name, bt_info->piece_length);
	temp = info + bytescopied;
	for (j = 0; j < bt_info->num_pieces; j++)
	{
		strncat(temp, bt_info->piece_hashes[j], HASH_LENGTH);
		temp += HASH_LENGTH;
		bytescopied += HASH_LENGTH;
	}

//	printf("Value of Info string: %s and size is %d\n", info + 123, bytescopied);

	//Calculating SHA1 for info string

	SHA1((unsigned char *)info, bytescopied, (unsigned char *)md);
	//printf("Hash of info is %s and its length is %d\n", md, (int)strlen(md));
	//for (i = 0; i < 20; i++) printf("0x%02x ", (unsigned char)(md[i]));
//	hexdump(md,20);

	return bt_info;
}



//The master thread (main) uses this function to maintain fetch a connection number and checks for connection overflow condition.
int get_nxt_available_conn()
{
	int i;
	for (i = 0; i < MAX_CONNECTIONS; i++){
		if (connections[i] == AVAILABLE)
			return i;
	}
	return UNAVAILABLE;
}

//A thread uses this function to set the availability of the connection number while exiting.
void update_connections(int i)
{
	if (pthread_mutex_lock(&lock)) {
		perror("pthread_mutex_lock");
		exit(1);
	}

	connections[i] = AVAILABLE;

	if (pthread_mutex_unlock(&lock)) {
		perror("pthread_mutex_unlock");
		exit(1);
	}
}

