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
#include <openssl/sha.h>
#include <pthread.h>


#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include "bt_sock.h"
#include "bt_file.h"

bt_msg_t * make_request(bt_args_t *bt_args, bt_bitfield_t *server_bitfield, int clientno);
int downloadfield_isSet(int bit);
int bitfield_isSet(bt_bitfield_t *bitfield, int bit);
bt_msg_t * generate_bitfieldmsg(bt_args_t *bt_args); //bt_args
void print_msg(bt_msg_t msg);

static int download_bits[MAX_CONNECTIONS] = {-1,-1,-1,-1,-1};
double save_percent = 0;
int num_saved_pieces = 0;
extern int ok_to_print;



/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t * peer, bt_msg_t *msg, int sockfd)
{
	void *recvbuf = NULL;
	
	int piece_length = 0;
	//reading the message length
	recvbuf = give_mem(recvbuf, sizeof(int));
	if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
	{
		printf("Receiving message length failed\n");
		free(recvbuf);
		return FAILURE;
	}
	memcpy(&msg->length, recvbuf, sizeof(int));
	//if msg->length is 0, it is a keep alive message

	//reading message type
	recvbuf = give_mem(recvbuf, sizeof(int));
	if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
	{
		printf("Receiving message type failed\n");
		free(recvbuf);
		return FAILURE;
	}
	memcpy(&msg->bt_type, recvbuf, sizeof(int));

	switch (msg->bt_type){

	case BT_CHOKE://choke
	case BT_UNCHOKE://unchoke
	case BT_INTERSTED: //interested
	case BT_NOT_INTERESTED: //not intereseted
		break;
	case BT_HAVE: //have
		break;
	case BT_BITFILED: //bit_field
		recvbuf = give_mem(recvbuf, sizeof(size_t));
		if (recvData(sockfd, recvbuf, sizeof(size_t)) == FAILURE)
		{
			printf("Receiving size of the bitfield failed\n");
			free(recvbuf);
			return FAILURE;
		}
		memcpy(&msg->payload.bitfield.size, recvbuf, sizeof(size_t));

		recvbuf = give_mem(recvbuf, msg->payload.bitfield.size);
		if (recvData(sockfd, recvbuf, msg->payload.bitfield.size) == FAILURE)
		{
			printf("Receiving size of the bitfield failed\n");
			free(recvbuf);
			return FAILURE;
		}
		msg->payload.bitfield.bitfield = give_mem(NULL, msg->payload.bitfield.size);
		memcpy(msg->payload.bitfield.bitfield, recvbuf, msg->payload.bitfield.size);
		//change#
		//for (i = 0; i < msg->payload.bitfield.size; i++)
		free(recvbuf);
		break;


	case BT_REQUEST: //request
	case BT_CANCEL: //cancel
		recvbuf = give_mem(recvbuf, sizeof(int));
		if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
		{
			printf("Receiving index from request failed\n");
			free(recvbuf);
			return FAILURE;
		}
		memcpy(&msg->payload.request.index, recvbuf, sizeof(int));

		bzero(recvbuf, sizeof(int));
		if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
		{
			printf("Receiving begin from request failed\n");
			free(recvbuf);
			return FAILURE;
		}
		memcpy(&msg->payload.request.begin, recvbuf, sizeof(int));

		bzero(recvbuf, sizeof(int));
		if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
		{
			printf("Receiving length from request failed\n");
			free(recvbuf);
			return FAILURE;
		}
		memcpy(&msg->payload.request.length, recvbuf, sizeof(int));
		free(recvbuf);
		break;

	case BT_PIECE: //piece
		bzero(recvbuf, sizeof(int));
		if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
		{
			printf("Receiving begin from request failed\n");
			return FAILURE;
		}
		memcpy(&msg->payload.piece.index, recvbuf, sizeof(int));

		bzero(recvbuf, sizeof(int));
		if (recvData(sockfd, recvbuf, sizeof(int)) == FAILURE)
		{
			printf("Receiving begin from request failed\n");
			return FAILURE;
		}
		memcpy(&msg->payload.piece.begin, recvbuf, sizeof(int));

		piece_length = msg->length - (3 * sizeof(int));

		recvbuf = give_mem(recvbuf, piece_length);

		if (recvData(sockfd, recvbuf, piece_length) == FAILURE)
		{
			printf("Receiving begin from request failed\n");
			return FAILURE;
		}
		msg->payload.piece.piece = (char *)recvbuf; // free this piece after writing into file	
		break;
	}

	
	return SUCCESS;
}


//writes message bt_msg_t *msg to socket sockfd
int send_to_peer(peer_t * peer, bt_msg_t *msg, int sockfd)
{
	void *sendbuf = NULL;
	int piece_length = 0;
	
	//sending the message length
	sendbuf = give_mem(sendbuf, sizeof(int));
	memcpy(sendbuf, &msg->length, sizeof(int));
	if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
	{
		printf("Sending message length failed\n");
		return FAILURE;
	}
	
	//reading message type
	sendbuf = give_mem(sendbuf, sizeof(int));
	memcpy(sendbuf, &msg->bt_type, sizeof(int));
	if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
	{
		printf("Sending message type failed\n");
		return FAILURE;
	}

	switch (msg->bt_type){

	case BT_CHOKE: //choke
	case BT_UNCHOKE: //unchoke
	case BT_INTERSTED: //interested
	case BT_NOT_INTERESTED: //not intereseted
		break;
	case BT_HAVE: //have
		break;
	case BT_BITFILED: //bit_field
		sendbuf = give_mem(sendbuf, sizeof(size_t));
		memcpy(sendbuf, &msg->payload.bitfield.size, sizeof(size_t));
		if (sendData(sockfd, sendbuf, sizeof(size_t)) == FAILURE)
		{
			printf("Sending size of the bitfield failed\n");
			return FAILURE;
		}
		

		sendbuf = give_mem(sendbuf, msg->payload.bitfield.size);
		memcpy(sendbuf, msg->payload.bitfield.bitfield, msg->payload.bitfield.size);
		if (sendData(sockfd, sendbuf, msg->payload.bitfield.size) == FAILURE)
		{
			printf("Sending size of the bitfield failed\n");
			return FAILURE;
		}
		
		break;

	case BT_REQUEST: //request
	case BT_CANCEL: //cancel
		sendbuf = give_mem(sendbuf, sizeof(int));
		memcpy(sendbuf, &msg->payload.request.index, sizeof(int));
		if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
		{
			printf("Sending index from request failed\n");
			return FAILURE;
		}
		
		sendbuf = give_mem(sendbuf, sizeof(int));
		memcpy(sendbuf, &msg->payload.request.begin, sizeof(int));
		if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
		{
			printf("Sending begin from request failed\n");
			return FAILURE;
		}
		

		sendbuf = give_mem(sendbuf, sizeof(int));
		memcpy(sendbuf, &msg->payload.request.length, sizeof(int));
		if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
		{
			printf("Sending length from request failed\n");
			return FAILURE;
		}
		
	
		break;

	case BT_PIECE: //piece
		sendbuf = give_mem(sendbuf, sizeof(int));
		memcpy(sendbuf, &msg->payload.piece.index, sizeof(int));
		if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
		{
			printf("Sending index from request failed\n");
			return FAILURE;
		}
		
		sendbuf = give_mem(sendbuf, sizeof(int));
		memcpy(sendbuf, &msg->payload.piece.begin, sizeof(int));
		if (sendData(sockfd, sendbuf, sizeof(int)) == FAILURE)
		{
			printf("Sending begin from request failed\n");
			return FAILURE;
		}
		
		piece_length = msg->length - (3 * sizeof(int));

		sendbuf = give_mem(sendbuf, piece_length);
		memcpy(sendbuf, msg->payload.piece.piece, piece_length);
		if (sendData(sockfd, sendbuf, piece_length) == FAILURE)
		{
			printf("Sending piece data from request failed\n");
			return FAILURE;
		}
		break;


	}

	free(sendbuf);
	return SUCCESS;
}


//Used for testing pthreads
void test(void * args)
{
	int i;
	bt_args_t *bt_args;

	printf("Inside Mutex");
	pthread_func_args my_args = *((pthread_func_args *)args);
	bt_args = &my_args.bt_args;

	if (my_args.bt_args.verbose){
		printf("Thread number : %d\n", my_args.clientno);
		printf("Args:\n");
		printf("verbose: %d\n", bt_args->verbose);
		printf("save_file: %s\n", bt_args->save_file);
		printf("log_file: %s\n", bt_args->log_file);
		printf("torrent_file: %s\n", bt_args->torrent_file);
		printf("Self id: ");
		for (i = 0; i < ID_SIZE; i++){
			printf("0x%02x ", (unsigned char)bt_args->selfid[i]);
		}
		for (i = 0; i < MAX_CONNECTIONS; i++){
			if (my_args.bt_args.peers[i] != NULL)
				print_peer(my_args.bt_args.peers[i]);
		}


	}

}


//thread function for the leecher
void client_func(void *args)
{

	pthread_func_args my_args = *((pthread_func_args *)args);
	bt_args_t *bt_args = &my_args.bt_args;
	int clientno = my_args.clientno;
	struct sockaddr_in addr;
	int len = sizeof(struct sockaddr);
	int i = 0;
	bt_msg_t *msg_from_server = NULL;
	bt_msg_t *request_msg = NULL;
	bt_msg_t *piece_msg = NULL;
	bt_msg_t *interest_msg = NULL;
	int piecelen = 0, index = 0;
	unsigned char piecesha1[20];

	char tag[15];
	bzero(tag,15);
	sprintf(tag,"LEECHER#%d",clientno);

	char mymsg[100];
	char *temp;
	
	getsockname(bt_args->sockets[clientno], (struct sockaddr *) &addr, (socklen_t *)&len);
	printf("[%s] - Connected to a Seeder at IP %s and Port %d\n",tag, inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
	logger(LOG, tag, "THREAD ID : %u\n", (unsigned int)pthread_self());
	logger(LOG,tag,"SEEDER IP ADDR %s AND PORT %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));


	//PRINT("\n\n\n\n****************************************************************\n\n");
	logger(LOG, tag, "INIT HANDSHAKE\n");
	//Start handshake sequence....return if not successful
	if (init_handshake(bt_args->peers[clientno], (unsigned char *)bt_args->info_hash, (unsigned char *)bt_args->selfid, bt_args->sockets[clientno]) == FAILURE)
	{
		printf("[%s] - Handshake with peer failed\n", tag);//and start a client thread to start the transfer
		logger(LOG, tag, "HANDSHAKE FAILED\n");
		//exit sequence
		shutdown(bt_args->sockets[clientno], SHUT_RDWR);
		update_connections(clientno);
		return;
	}
	else { 
		printf("[%s] - HANDSHAKE SUCCESS\n",tag); 
		logger(LOG,tag,"HANDSHAKE SUCCESS\n");
	}
	while (TRUE)
	{
		//**************Recv Server bitfield msg*******************************//
		PRINT("Waiting for server's bitfield\n");
		msg_from_server = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		if (read_from_peer(bt_args->peers[clientno], msg_from_server, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("[%s] - Reading bitfield from server failed\n",tag);
			logger(LOG, tag, "MESSAGE - Reading bitfield from server failed\n");
			break;
		}

		bzero(mymsg, 100);
		temp = mymsg;
		for (i = 0; i < msg_from_server->payload.bitfield.size;i++)
		temp += sprintf(temp, "0x%02x ", (unsigned char)msg_from_server->payload.bitfield.bitfield[i]);

		PRINT("[%s] - Received bitfield mesage\n",tag);
		logger(LOG, tag, "MESSAGE RCVD : BITFIELD - %s\n", mymsg);
		printf("[%s] - MESSAGE RCVD : BITFIELD - %s\n", tag, mymsg);
		print_msg(*msg_from_server);

		//**************Recv Server bitfield msg*******************************//

		//**************Send interest and Request msg*******************************//
		PRINT("[%s] - Sending Interested/NotInterested Message\n",tag);
		interest_msg = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		interest_msg->length = sizeof(unsigned int);
		
		if ((request_msg = make_request(bt_args, &(msg_from_server->payload.bitfield),clientno)) == NULL)
		{
			interest_msg->bt_type = BT_NOT_INTERESTED;
			send_to_peer(bt_args->peers[clientno], interest_msg, bt_args->sockets[clientno]);
			print_msg(*interest_msg);
			printf("[%s] - MESSAGE SENT : NOT INTERESTED\n",tag);
			logger(LOG, tag, "MESSAGE SENT : NOT INTERESTED\n");
			break;//exit sequence
		}
		
		//else interested
		printf("[%s] - MESSAGE SENT : INTERESTED\n",tag);
		logger(LOG, tag, "MESSAGE SENT : INTERESTED\n");
		interest_msg->bt_type = BT_INTERSTED;
		if (send_to_peer(bt_args->peers[clientno], interest_msg, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("[%s] - Sending interest msg failed!!\n",tag);
			logger(LOG, tag, " Sending interest message to seeder failed\n");
			break;
		}
		
		
		PRINT("[%s] - Printing the interest msg being sent\n",tag);
		print_msg(*interest_msg);
		
		free(interest_msg);
		//free(msg_from_server->payload.bitfield.bitfield);
		//free(msg_from_server);
		//Send request message
		
		logger(LOG, tag, "MESSAGE SENT: REQUEST : INDEX - %d, OFFSET - %d, LENGTH - %d\n", request_msg->payload.request.index, request_msg->payload.request.begin, request_msg->payload.request.length);
		printf("[%s] - MESSAGE SENT: REQUEST : INDEX - %d, OFFSET - %d, LENGTH - %d\n", tag, request_msg->payload.request.index, request_msg->payload.request.begin, request_msg->payload.request.length);
		PRINT("Sending request message:\n");
		print_msg(*request_msg);

		piecelen = request_msg->payload.request.length;
		index = request_msg->payload.request.index;

		if(send_to_peer(bt_args->peers[clientno], request_msg, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("[%s] - Sending Request msg failed!!\n",tag);
			logger(LOG, tag, " Sending request message to seeder failed\n");
			break;
		}

		//**************Send interest and Request msg*******************************//
		PRINT("[%s] - Waiting for the file piece requested\n", tag);
		piece_msg = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		//receive piece message
		if (read_from_peer(bt_args->peers[clientno], piece_msg, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("[%s] - Receiving piece msg failed\n",tag);
			logger(LOG, tag, " Receiving piece msg failed\n");
			break;
		}
		
		PRINT("Received piece message\n");
		print_msg(*piece_msg);
		logger(LOG, tag, "MESSAGE RCVD : PIECE : INDEX - %d, OFFSET - %d\n", piece_msg->payload.piece.index, piece_msg->payload.piece.begin);
		printf("[%s] - MESSAGE RCVD : PIECE : INDEX - %d, OFFSET - %d\n", tag, piece_msg->payload.piece.index, piece_msg->payload.piece.begin);

		SHA1((unsigned char *)piece_msg->payload.piece.piece, piecelen, piecesha1);
		if (!compare((unsigned char *)piecesha1, (unsigned char *)bt_args->bt_info->piece_hashes[index], 20))
		{
			printf("[%s] - Piece sha1 not matched...Discarding the piece\n",tag);
			logger(LOG, tag, "Piece sha1 not matched...Discarding the piece\n");
		}
		else
		{
			//get lock on file mutex
			
			//logger(LOG, tag, "SAVING %d BYTES TO FILE\n", piecelen);
			//save the received piece to file
			if ((save_piece(bt_args, &(piece_msg->payload.piece), piecelen)) == FAILURE)
			{
				printf("[%s] - Saving the piece failed\n", tag);
				logger(LOG,tag, "Saving the piece failed\n");
			}
		
			//update the global bitfield array
			sethavepiece(piece_msg->payload.piece.index + 1, YES);
			//release lock on file mutex 
		}
		//logger(LOG,tag,"Sleeping for 5 seconds\n");
		//sleep(5);
		#ifdef _SLEEP_
		logger(LOG,tag,"Sleeping for 5 seconds\n");
		//SLEEP;
		sleep(5);
		logger(LOG,tag,"Sleep Timeout\n");
		#endif
		
		//cleanup#
		free(piece_msg->payload.piece.piece);
		//free(piece_msg);
		free(request_msg);
		//done downloading the piece at requested index
		download_bits[clientno] = -1;
		
	}


	shutdown(bt_args->sockets[clientno], SHUT_RDWR);
	update_connections(clientno);
	printf("[%s] - Terminating Connection with Seeder\n", tag);
	logger(LOG, tag, "TERMINATING CONNECTION WITH SEEDER\n");
	printf("\n\n\n\n****************************************************************\n\n");
	//return SUCCESS;
}

//thread function for the seeder
void server_func(void *args)
{
	pthread_func_args my_args = *((pthread_func_args *)args);
	bt_args_t *bt_args = &my_args.bt_args;
	int clientno = my_args.clientno;
	struct sockaddr_in addr;
	int len = sizeof(struct sockaddr);
	bt_msg_t *msg_to_client = NULL;
	bt_msg_t *piece_msg = NULL;

	char tag[15];
	bzero(tag, 15);
	sprintf(tag, "SEEDER #%d", clientno);


	getsockname(bt_args->sockets[clientno], (struct sockaddr *) &addr, (socklen_t *)&len);
	printf("[%s] - Leecher connected at IP %s and Port %d\n", tag, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	logger(LOG, tag, "THREAD ID : %u\n", (unsigned int)pthread_self());
	logger(LOG, tag, "LEECHER IP ADDR %s\n", inet_ntoa(addr.sin_addr));


	PRINT("\n\n\n\n****************************************************************\n\n");
	printf("[%s] - RESPONSE HANDSHAKE\n",tag); 
	logger(LOG,tag,"RESPONSE HANDSHAKE\n");
	if (response_handshake(bt_args->peers[clientno], (unsigned char *)bt_args->info_hash, (unsigned char *)bt_args->selfid, bt_args->sockets[clientno]) == FAILURE)
	{
		printf("response_handshake Failed\n");//and start a client thread to start the transfer
		//exit sequence
		shutdown(bt_args->sockets[clientno], SHUT_RDWR);
		update_connections(clientno);
		return;
		//return FAILURE;
	}
	PRINT("\nHANDSHAKE SUCCESS\n");
	printf("[%s] - HANDSHAKE SUCCESS\n",tag); 
	logger(LOG,tag,"HANDSHAKE SUCCESS\n");
	
	while (TRUE)
	{
		//**************Send bitfield msg*******************************//
		msg_to_client = generate_bitfieldmsg(bt_args);

		PRINT("\nGenerated Bitfield and sending to client\n");
		print_msg(*msg_to_client);

		if (send_to_peer(bt_args->peers[clientno], msg_to_client, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("send_to_peer failed\n");
			break;
		}
		logger(LOG, tag, "MESSAGE SENT : BITFIELD \n");
		printf("[%s] - MESSAGE SENT : BITFIELD \n", tag);
		
		
		free(msg_to_client->payload.bitfield.bitfield);
		//free(msg_to_client);
		
			
		//**************Recv Interested msg*******************************//
		PRINT("Waiting for Interested Message from Client\n");
		msg_to_client = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		if (read_from_peer(bt_args->peers[clientno], msg_to_client, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("read_from_peer failed\n");
			break;
		}
		PRINT("Message Received:\n");	
		print_msg(*msg_to_client);
		
		if (msg_to_client->bt_type == BT_NOT_INTERESTED)
		{
			printf("[%s] - MESSAGE RCVD : NOT INTERESTED\n",tag);
			logger(LOG, tag, "MESSAGE RCVD : NOT INTERESTED\n");
			break;
		}
		
		printf("[%s] - MESSAGE RCVD : INTERESTED\n",tag);
		logger(LOG, tag, "MESSAGE RCVD : INTERESTED\n");
		

		free(msg_to_client);
		
		//**************Recv Request msg*******************************//

		//read from peer the request message
		msg_to_client = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		if (read_from_peer(bt_args->peers[clientno], msg_to_client, bt_args->sockets[clientno]) == FAILURE)
		{
			printf("read_from_peer failed\n");
			free(msg_to_client);
			break;
		}

		
		PRINT("\nReading the Request msg received\n");
		print_msg(*msg_to_client);
		logger(LOG, tag, "MESSAGE RCVD: REQUEST: INDEX - %d, OFFSET - %d, LENGTH - %d\n", msg_to_client->payload.request.index, msg_to_client->payload.request.begin, msg_to_client->payload.request.length);
		printf("[%s] - MESSAGE RCVD: REQUEST: INDEX - %d, OFFSET - %d, LENGTH - %d\n", tag, msg_to_client->payload.request.index, msg_to_client->payload.request.begin, msg_to_client->payload.request.length);
	
		//**************Send Piece msg*******************************//
		PRINT("\nSending the requested piece\n");
		piece_msg = (bt_msg_t *)give_mem(NULL, sizeof(bt_msg_t *));
		//Load piece message
		if ((load_piece(bt_args->bt_info, &(msg_to_client->payload.request), &piece_msg->payload.piece)) == FAILURE)
		{
			printf("Loading piece msg failed\n");
			if (piece_msg->payload.piece.piece != NULL)
				free(piece_msg->payload.piece.piece);
			free(piece_msg);
			free(msg_to_client);
			break;
		}
		piece_msg->length = sizeof(unsigned int)+(2 * sizeof(int)) + msg_to_client->payload.request.length;
		piece_msg->bt_type = BT_PIECE;
		
		print_msg(*piece_msg);
		//Send the piece message to peer
		
		logger(LOG, tag, "MESSAGE SENT: PIECE : INDEX - %d, OFFSET - %d\n", piece_msg->payload.piece.index, piece_msg->payload.piece.begin);
		printf("[%s] - MESSAGE SENT : PIECE : INDEX - %d, OFFSET - %d\n", tag, piece_msg->payload.piece.index, piece_msg->payload.piece.begin);


		if (send_to_peer(bt_args->peers[clientno], piece_msg, bt_args->sockets[clientno]) == FAILURE)
		{
			PRINT("send_to_peer failed\n");
			if (piece_msg->payload.piece.piece != NULL)
				free(piece_msg->payload.piece.piece);
			//free(piece_msg);
			//free(msg_to_client);
			break;
		}
		else
		{//done with piece_msg
			if (piece_msg->payload.piece.piece != NULL)
				free(piece_msg->payload.piece.piece);
			//free(piece_msg);
			//free(msg_to_client);
		}
		
	}

	printf("[%s] - TERMINATING THE CONNECTION WITH LEECHER\n",tag);
	logger(LOG, tag, "TERMINATING THE CONNECTION WITH LEECHER\n");
	
	shutdown(bt_args->sockets[clientno], SHUT_RDWR);
	update_connections(clientno);

	PRINT("\n\n\n\n****************************************************************\n\n");
	//return SUCCESS;
}


//to print a bittorrent message on the console
void print_msg(bt_msg_t msg)
{
	int i;

	if (!ok_to_print)
		return;

	printf("\n/***********MESSAGE***********/\n");
	printf("msg.length : %d\n",msg.length);
	

	switch (msg.bt_type){

	case BT_CHOKE: //choke
		printf("msg.bt_type : BT_CHOKE\n"); break;
	case BT_UNCHOKE: //unchoke
		printf("msg.bt_type : BT_UNCHOKE\n"); break;
	case BT_INTERSTED: //interested
		printf("msg.bt_type : BT_INTERSTED\n"); break;
	case BT_NOT_INTERESTED: //not intereseted
		printf("msg.bt_type : BT_NOT_INTERESTED\n"); break;
	case BT_HAVE: //have
		printf("msg.bt_type : BT_HAVE\n");
		break;
	case BT_BITFILED: //bit_field
		printf("msg.bt_type : BT_BITFILED\n");
		for (i = 0; i < msg.payload.bitfield.size; i++)
		printf("msg.payload.bitfield.bitfield : %02x\n", (unsigned char)msg.payload.bitfield.bitfield[i]);
		printf("msg.payload.bitfield.size : %d\n", (int)msg.payload.bitfield.size);
		break;


	case BT_REQUEST: //request
		
	case BT_CANCEL: //cancel
		printf("msg.bt_type : %s\n", (msg.bt_type == BT_CANCEL)?"BT_CANCEL":"BT_REQUEST");
		printf("msg.payload.request.index : %d\n", msg.payload.request.index);
		printf("msg.payload.request.begin : %d\n", msg.payload.request.begin);
		printf("msg.payload.request.length : %d\n", msg.payload.request.length);
		break;

	case BT_PIECE: //piece
		printf("msg.bt_type : BT_PIECE\n");
		printf("msg.payload.piece.index : %d\n", msg.payload.piece.index);
		printf("msg.payload.piece.begin : %d\n", msg.payload.piece.begin);
		break;
	}
	
	printf("\n/********END OF MESSAGE********/\n");
}


//creates the bitfiled message
bt_msg_t * generate_bitfieldmsg(bt_args_t *bt_args) //bt_args
{
	bt_msg_t *msg = NULL;
	bt_bitfield_t *bitfield_temp;

	msg = (bt_msg_t *)give_mem(msg, sizeof(bt_msg_t *));
	bitfield_temp = get_bitfield(bt_args);

	msg->bt_type = BT_BITFILED;
	msg->payload.bitfield.size = bitfield_temp->size;
	msg->length = sizeof(unsigned int) + sizeof(size_t) + msg->payload.bitfield.size;
	msg->payload.bitfield.bitfield = (char *)give_mem(NULL,msg->payload.bitfield.size);
	
	memcpy(msg->payload.bitfield.bitfield, bitfield_temp->bitfield, bitfield_temp->size);
	
	//cleanup
	free(bitfield_temp);

	return msg;
}

//creates the request message
bt_msg_t * make_request(bt_args_t *bt_args, bt_bitfield_t *server_bitfield, int clientno)
{
	bt_msg_t * requestMsg = NULL;
	bt_bitfield_t *client_bitfield = NULL;
	int isSetClient = 0, isSetServer = 0, isSetBit = 0;
	int piece_to_request = -1;
	int i, piecelength;
	

	// check what pieces the client has, i.e., compute the bitfield of client
	client_bitfield = get_bitfield(bt_args);


	//read the bitfield of the server to check what pieces it has and to decide which piece is required

	for (i = 0; i < bt_args->bt_info->num_pieces; i++)
	{
		isSetClient = bitfield_isSet(client_bitfield, i);
		isSetServer = bitfield_isSet(server_bitfield, i);
		if ((isSetServer == 1) && (isSetClient == 0)) //also check if any other thread is downloading the same piece
		{
			isSetBit = downloadfield_isSet(i);
			if (isSetBit) continue;
			else
			{
				piece_to_request = i;
				break;
			}
		}

	}

	//cleanup# 
	free(client_bitfield->bitfield);
	free(client_bitfield);

	if (piece_to_request == -1) return NULL;
	
	download_bits[clientno] = piece_to_request;
	if (((piece_to_request + 1) * bt_args->bt_info->piece_length) > bt_args->bt_info->length)
	{//last piece
		piecelength = bt_args->bt_info->length % bt_args->bt_info->piece_length;
	}
	else
	{
		piecelength = bt_args->bt_info->piece_length;
	}
	

	// form the request message to send
	requestMsg = (bt_msg_t *)malloc(sizeof(bt_msg_t));
	requestMsg->length = sizeof(unsigned int) + sizeof(bt_request_t);
	requestMsg->bt_type = BT_REQUEST;
	requestMsg->payload.request.index = piece_to_request;
	requestMsg->payload.request.begin = 0;
	requestMsg->payload.request.length = piecelength;



	return requestMsg;
}


//checks if a particular piece represented by bit exists in the bitfield
int bitfield_isSet(bt_bitfield_t *bitfield, int bit)
{
	int isSet = 0;
	int byte = bit / 8;
	int mask = 0x01;
	int position = (bit % 8);
	isSet = (bitfield->bitfield[byte] >> (7-position)) & mask;
	return isSet;
}

//checks if a given piece is currently downloaded from any of the seeders
int downloadfield_isSet(int bit)
{
	int i;
	for (i = 0; i < MAX_CONNECTIONS; i++)
	{
		if (download_bits[i] == bit)
			return TRUE;

	}
	return FALSE;
}



