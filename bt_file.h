//standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <poll.h>

//networking stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "bt_lib.h"
#include "bencode.h"

#define LOG_FILE "bt-client.log"
#define LOCKED_FILE_RETRY_TIME 3
#define LOCKED_FILE_TIMEOUT 15
#define HAVE 'h'
#define DONT_HAVE 'd'
#define YES 1
#define NO 0
#define FILE_EXISTS 1
#define NEW_FILE_CREATED 0


//void logger(const char* tag, const char* message);

void logger(int flag, const char* tag, const char* fmt, ...);

int preparefile(char * filename, off_t size);

void preparehavepiece(int no_of_pieces);

void sethavepiece(int index, int as);

void bitfield_set(bt_bitfield_t *newbitfield, int bit);

bt_bitfield_t * computebitfield(int no_of_pieces);
// , bt_bitfield_t * newbitfield);

//int get_bitfield(bt_args_t * bt_args, bt_bitfield_t * bitfield);
bt_bitfield_t * get_bitfield(bt_args_t * bt_args);

int save_piece(bt_args_t * bt_args, bt_piece_t * piece,int piecelen);

int load_piece(bt_info_t * bt_info, bt_request_t *request, bt_piece_t * piece);


void releaselock(FILE *file);

FILE * acquirelockon(char *filename, char *access);
