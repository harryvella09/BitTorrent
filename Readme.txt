README

********************************************************
Description of the program:
********************************************************

    This program demonstrates basic bitTorrent client functionality with N   seeders and N leechers and restarts are allowed.
    Multiple peers are implemented using pthreads and coherency is maintained using mutex locks.
	
	
	The code flow for a seeder is as follows:
	
	The seeder creates a listening socket and binds to the available system ip address and a random port number. The ip 
	address to bind can also be specified using -b option. On receiving an incoming connection, a new thread is started 
	to serve the leecher and the seeder continues to listen for other incoming connections. The seeder can serve a maximum
	of five leechers simultaneously.
	
	Each seeder thread runs in the following manner:
	1) Waits for the initial handshake, compares the received protocol name, name length and hash info values and if matching, 
	   sends a response handshake. If not, connection is dropped. The peer id received is updated in its peer list. 
	2) Once the handshake is successful, the seeder sends its bitfield to the leecher and waits for interested message. 
	   Upon receipt of interest and a request message, the seeder sends the piece requested.
	3) Once the piece is received, the seeder again sends bitfield and the loop goes on until the leecher is no more 
	   interested in any of the pieces.
	   
	   
	The code flow for a leecher is as follows:
	
	The leecher creates a socket and connects to the seeder on the given ip address and port number using the -p option.
	The leecher can connect to a maximum of five seeders simultaneously using multiple -p options. Once the connection
	is established, a pthread is created for each connection and each thread executes the following sequence.
	
	Each leecher thread runs in the following manner:
	1) The leecher initiates the handshake and waits for the response handshake. Upon receiving the response, it compares 
	   the peer id of the seeder with the value it has. If the value does not match, the connection is dropped.
	2) On handshake success, the leecher waits for the bitfield of the server. On receiving, it will compare with its
	   own bitfield, checks if any piece is required and sends an interested message followed by request message. If
	   not required, it will send not interested message and exit the sequence.
	3) The leecher now waits for the requested piece. On receiving the piece, it makes the hash of the piece, compares
	   it with the piece hash. If the hash matches, it will save the piece else discard it.
	4) After this, the leecher goes back to waiting for seeder bitfield.
	
	A logger has been implemented in bt_file.c to log the important events and messages with timestamp. Download progress
	is also indicated after successful download of each piece both into the log file and console.
	
	*********************************************************************
	Included Files and Purpose
       **********************************************************************
	bt_client.c   :   Main file where the control loop lives
	bt_setup.c    :   Contains setup code, such as parsing arguments
	bencode.c     :   Code for parsing bencoded torrent files
	bt_lib.c      :   Code for core functionality of bt

	bt_setup.h    :   Header file for setup
	bencode.h     :   Header file for bencode
	bt_lib.h      :   Header file for bt_lib

	Additional files written
        ************************
	peer.c[.h]    :   File for handling seeder and leecher thread functions, 
					  creating the bittorrent messages and sending/receiving them
	bt_file.c[.h] :   File for reading and writing data from/to the files, 
					  implementation of logger
	bt_sock.c[.h] :   File for creating a socket, to establish connection with peer, 
	                  read and write to sockets.

       **********************************************************************  		Untaring the program modules:
       **********************************************************************

         Untar AssignmentThree.tar.gz file in a folder using the following command:

                tar -zxvf AssignmentTwo.tar.gz


	********************************************************
	Compilation procedure:
	********************************************************
        
		To compile using makefile, use the following command:

        1)make clean
                This removes the previously generated object files and binary files if exists.

        2)make
                This command compiles the .c files and generates the necessary object and binary files.

	3) make num='value' client:
		eg: make num=1 client
		This command creates a directory client1 and copies the
executable and torrent files to that directory.

	4) make sleep
		For demo purpose, we have introduced sleep after each piece  is downloaded by the leecher thread. This is enabled using -D option in the
makefile. 
        
	********************************************************
	Program Execution:
	********************************************************

	Each peer runs as both seeder and leecher.
	
        To run as seeder, Use the following in the command line
		./bt_client <torrent file name>
		
		Variations:
	
		1) -s option: can specify the file needs to be seeded rather than the default file name specified in the 
					  torrent file.
			eg: if a file was downloaded with a name other than the one specified in the torrent file, it can be seeded
				using -s option
					
			Usage: ./bt_client -v -s <filename to seed> -b <ip address in dot format> <torrent file name>

		Once the seeder is started, the leecher can be started using the following command line with -p option:
		
		1) -p option :
		 
		 ./bt_client -p <IPaddress:listening_portno of seeder> <torrent file name>
		
		Multiple -p options are used to connect to many seeders at once.
		
		2) -s option: Used to save the received file for a specifed name.
		
			Usage: ./bt_client -s <filename to save> -p <IPaddress:listening_portno of seeder> <torrent file name>

				
		Other options:
		
		1) -v option: to enable verbose
			Usage: ./bt_client -v -b <ip address in dot format> <torrent file name>

		
		2) -l option: to specify the log file name. By default, logger writes to bt-client.log
			
			Usage: ./bt_client -v -s <filename to seed> -b <ip address in dot format> <torrent file name> -l <log file>
			
		3) -I option: Used to specify the self ID but in this case, it is not implemented rather handled.
		
		4) -h option: to display help screen.
		
		5) -b option: To bind to a specific ip address available on the machine
			Usage: ./bt_client -b <ip address in dot format> <torrent file name>

		
	********************************************************
	Output Interpretation:
	********************************************************

		The entire output is logged in bt-client.log by default. This log file consists of the entire sequence of messages and events. Verbose contains a more detailed explanation of messages and events.
		
		
		
		
