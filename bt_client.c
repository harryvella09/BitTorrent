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
#include <pthread.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include "bt_sock.h"
#include "bt_file.h"
#include "peer.h"





int connections[MAX_CONNECTIONS] = { AVAILABLE, AVAILABLE, AVAILABLE, AVAILABLE, AVAILABLE };
int ok_to_print = FALSE;


int main (int argc, char * argv[]){

  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  bt_info_t * info_node;
  int i;

  pthread_t my_thread[5];
  pthread_func_args my_args[5];

  char s[INET6_ADDRSTRLEN];
  int listeningSock;
  int client_sock, peer_sock;
  socklen_t client_addr_len;
  struct sockaddr_storage client_addr;
  char client_host[256];
  char client_port[32];
  unsigned char info_hash[ID_SIZE];

  unsigned char *myid = (unsigned char *)malloc(ID_SIZE);

  parse_args(&bt_args, argc, argv);


  if(bt_args.verbose){
	ok_to_print = TRUE;
    printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }

    
  }

  //read and parse the torrent file
  node = load_be_node(bt_args.torrent_file);
  info_node = extract_info(node, (char *)&info_hash);
  bt_args.bt_info = info_node;
  //Update the bt_args with info hash
  memcpy(&(bt_args.info_hash), &info_hash, ID_SIZE);

  if(bt_args.verbose){
    be_dump(node);
  }
  
  //Create a listening Socket for incoming requests
  listeningSock = create_listening_sock((char *)myid);
  //Update the self id in bt_args
  memcpy(&(bt_args.selfid), myid, ID_SIZE);
  free(myid);

  //make connections available
  for (i = 0; i < MAX_CONNECTIONS; i++){
	  connections[i] = AVAILABLE;
  }


  /* initialize mutex */
  if (pthread_mutex_init(&lock, NULL)) {
	  perror("pthread_mutex_init");
	  exit(1);
  }

  //Check through the peers structure and start pthreads for each peer

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        {
			peer_sock =  connectTopeer(inet_ntoa(bt_args.peers[i]->sockaddr.sin_addr),bt_args.peers[i]->port);

			if (peer_sock > 0)
			{//successfully connected to peer with out errors.........update the connection every where
				bt_args.sockets[i] = peer_sock;
				connections[i] = UNAVAILABLE;

				my_args[i].bt_args = bt_args;
				my_args[i].clientno = i;
				
				if (pthread_create(&my_thread[i], NULL, (void *)client_func, &my_args[i]) != 0){
					perror("pthread_create");
					exit(FAILURE);
				}
				printf("LEECHER : Created leecher thread id=%u\n", (unsigned int)my_thread[i]);
				logger(LOG,"LEECHER","Created leecher thread id=%u\n", (unsigned int)my_thread[i]);

			}
			else
			{
				printf("failed to connect with peer %d\n",i);
				//clean up the peer list 
				free(bt_args.peers[i]);
				bt_args.peers[i] = NULL;
			}
	}

	
    }

  //main client loop
  printf("Starting Main Loop\n");
  

   while(TRUE){

	   printf("Listening on socket for incoming connections\n");
	//try to accept incoming connection from new peer
    client_sock = accept(listeningSock, (struct sockaddr *)&client_addr, &client_addr_len);    


	inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), s, sizeof s);
	
	if (getnameinfo((const struct sockaddr *) &client_addr, sizeof(client_addr), client_host, sizeof(client_host), client_port, sizeof(client_port), 0) == 0)
	{
		printf("Client Host address: %s, Client Port: %s,client sock : %d\n", client_host, client_port, client_sock);
	}

	
	//Clean up the bt_args to remove stale connections
	for (i = 0; i < MAX_CONNECTIONS; i++){
		if ((connections[i] == AVAILABLE) & (bt_args.peers[i] != NULL))
		{//the client threads must have ended by now
			free(bt_args.peers[i]);
			bt_args.sockets[i] = -1;
			printf("Leecher thread id %u has joined the main thread\n", (unsigned int)my_thread[i]);
			logger(LOG, "PTHREAD", "CLEANING UP THREAD ID : %u\n", (unsigned int)my_thread[i]);
			pthread_join(my_thread[i],NULL);
		}
	}

	if ((client_sock > 0) & ((i = get_nxt_available_conn()) != UNAVAILABLE))
	{
		bt_args.peers[i] = (peer_t *)malloc(sizeof(peer_t));
		bt_args.sockets[i] = client_sock;
		connections[i] = UNAVAILABLE;
		
		my_args[i].bt_args = bt_args;
		my_args[i].clientno = i;

		if (pthread_create(&my_thread[i], NULL, (void *)server_func, &my_args[i]) != 0){
			perror("pthread_create");
			exit(FAILURE);
		}
		
		printf("SEEDER : created server thread id=%u\n", (unsigned int)my_thread[i]);
		logger(LOG, "SEEDER", "created server thread id=%u Client Host address: %s, Client Port: %s,client sock : %d, client no %d\n", (unsigned int)my_thread[i],client_host, client_port, client_sock, i);
		  
	}
	else if (client_sock < 0)
	{
		printf("SEEDER : Failed to connect with peer!!\n");
		logger(LOG,"SEEDER","Failed to connect with peer!!");
	}
	else if (i == UNAVAILABLE)
	{
		printf("Handling Maximum connections. Dropping the Request from ip %s and port no %d\n", s, ntohs(get_in_port((struct sockaddr *)&client_addr)));
		logger(LOG,"SEEDER","Handling Maximum connections. Dropping the Request from ip %s and port no %d\n", s, ntohs(get_in_port((struct sockaddr *)&client_addr)));
	}
   
    
}
   pthread_mutex_destroy(&lock);
  return 0;

}



